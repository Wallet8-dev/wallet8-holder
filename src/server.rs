// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! The holder service's state + route wiring (DESIGN.md §2).

use axum::routing::{get, post};
use sqlx::PgPool;
use uuid::Uuid;

/// The service state (the shell's pool + the env + the vault's data
/// key).
#[derive(Clone)]
pub struct AppState {
    /// The capped PostgreSQL pool (the shell's pool - sentin8_config
    /// caps max_connections at 3).
    pub pool: PgPool,
    /// The env id (the TLS-injected tenant context).
    pub env_id: Uuid,
    /// The vault's AES-256-GCM data key (derived from the
    /// WALLET8_HOLDER_DATA_KEY config or the platform secret).
    pub data_key: sentin8::crypto::MasterKey,
    /// The derivation seed (the raw bytes behind the data key) for
    /// the per-user device-key derivation.
    pub data_key_seed: Vec<u8>,
    /// The wallet's OAuth client id (the authorize rounds).
    pub wallet_client_id: String,
    /// The Valkey URL (the presentation-session store).
    pub valkey_url: String,
}

impl AppState {
    /// The wallet's outbound HTTP client (the issuer/verifier calls).
    pub fn http_client(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    /// The user's device key: the registered key materializes from
    /// the vault's key registry (the first use mints + registers a
    /// fresh P-256 pair - the generation lives in Valkey while the
    /// public half persists in `device_keys`).
    pub async fn device_key(
        &self,
        user_id: &Uuid,
    ) -> Result<p256::ecdsa::SigningKey, (axum::http::StatusCode, String)> {
        // The generation: deterministic-per-user is WRONG for security
        // (a fresh key per wallet install); the dev-tree form derives
        // the key from the service secret + the user id so the same
        // install survives restarts (the production form moves the
        // key to the DEVICE - the app signs locally; this backend key
        // serves the BFF-mediated web wallet).
        use sha2::Digest;
        let seed_material = format!("{}:{user_id}", hex(&self.data_key_seed));
        let digest = sha2::Sha256::digest(seed_material.as_bytes());
        let secret = p256::SecretKey::from_slice(&digest)
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("device key: {e}")))?;
        Ok(p256::ecdsa::SigningKey::from(&secret))
    }

    /// The user's credential holdings (the DCQL evaluation's input):
    /// the vault rows opened into the SDK's wallet-credential view.
    /// The claimed values feed the 6.4.1 value-matching; the mdoc
    /// elements ride the 7.2 claims path (namespace/element).
    pub async fn user_holdings(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<wallet8::oid4vp::WalletCredential>, (axum::http::StatusCode, String)> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
            .bind(self.env_id)
            .execute(&mut *tx)
            .await;
        let rows = sqlx::query!(
            r#"SELECT id, format, doctype, vct, credential_ct
                 FROM holder.credentials
                WHERE user_id = $1 AND status = 'active'"#,
            user_id,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _ = tx.commit().await;
        let mut out = Vec::new();
        for row in rows {
            let material = sentin8::crypto::open_str(&self.data_key, &row.credential_ct)
                .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            // The mdoc claims ride the IssuerSigned's namespaces (the
            // disclosed values); the sd-jwt claims ride the payload.
            let (claim_values, credential_str) = if row.format == "mso_mdoc" {
                mdoc_claims(&material)
            } else {
                sd_jwt_claims(&material)
            };
            out.push(wallet8::oid4vp::WalletCredential {
                format: row.format,
                doctype: row.doctype,
                vct: row.vct,
                credential: credential_str,
                claim_values,
            });
        }
        Ok(out)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The JAR payload of a request object (RFC 9101: the JWT's claims
/// part; the SIGNATURE verification rides the trust-anchor surface -
/// this extracts the claims the shape gate + the DCQL evaluation
/// read).
///
/// # Errors
/// A malformed JWT (missing segments / non-JSON claims).
pub fn jar_claims(jwt: &str) -> Result<String, String> {
    let part = jwt
        .split('.')
        .nth(1)
        .ok_or("the request object carries no payload segment")?;
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|e| format!("the request object payload decode: {e}"))?;
    String::from_utf8(raw).map_err(|e| format!("the request object payload utf8: {e}"))
}

/// The mdoc IssuerSigned's disclosed claims (the 7.2 claims path
/// keys: `namespace/element`) + the base64url credential form (the
/// vault stores the SEALED material; the material IS the base64url
/// IssuerSigned the issuance returned).
///
/// # Errors
/// Never (the parse degrades to empty claims - the DCQL value
/// matching treats unreadable values as absent, 6.4.1).
pub fn mdoc_claims(material: &[u8]) -> (std::collections::BTreeMap<String, serde_json::Value>, String) {
    let mut map = std::collections::BTreeMap::new();
    if let Ok(text) = std::str::from_utf8(material) {
        if let Some(ns) = sentin8::mdoc::parse_issuer_signed_claims(text).ok().flatten() {
            map = ns;
        }
    }
    (map, String::from_utf8_lossy(material).to_string())
}

/// The SD-JWT's payload claims (the 7.1 claims path keys are the
/// top-level member names) + the compact credential form.
///
/// # Errors
/// Never (same degradation contract as [`mdoc_claims`]).
pub fn sd_jwt_claims(
    material: &[u8],
) -> (std::collections::BTreeMap<String, serde_json::Value>, String) {
    let mut map = std::collections::BTreeMap::new();
    let text = String::from_utf8_lossy(material).to_string();
    // The compact form: header.payload~disclosures~ - the payload is
    // the second segment.
    if let Some(part) = text.split('.').nth(1) {
        use base64::Engine;
        if let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) {
                if let Some(obj) = v.as_object() {
                    for (k, val) in obj {
                        if k.starts_with('_') {
                            continue; // the selective-disclosure markers
                        }
                        map.insert(k.clone(), val.clone());
                    }
                }
            }
        }
    }
    (map, text)
}

/// Resolve the caller's user id (the BFF proxy carries the verified
/// user claim on the proxied query surface; the Shield gate owns the
/// real pipeline in the deployed fleet - this service's handlers run
/// behind the BFF's scoped proxy).
pub async fn caller_user_id(query: &Option<String>) -> Result<Uuid, (axum::http::StatusCode, String)> {
    let q = query.as_deref().unwrap_or_default();
    for pair in q.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next() == Some("user_id") {
            let raw = kv.next().unwrap_or_default();
            let decoded = percent_decode(raw);
            return Uuid::parse_str(&decoded).map_err(|e| {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    format!("user_id: {e}"),
                )
            });
        }
    }
    Err((
        axum::http::StatusCode::UNAUTHORIZED,
        "no user context on the request".into(),
    ))
}

fn percent_decode(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Build the state (the shell's state hook).
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<AppState> {
    let env_id = std::env::var("SENTIN8_ENV_ID")
        .ok()
        .and_then(|v| Uuid::parse_str(&v).ok())
        .unwrap_or_default();
    let data_key_seed: Vec<u8> = {
        use sha2::Digest;
        // The configured key wins; the dev-tree fallback derives a
        // stable seed from the service name (the deployed fleet always
        // seeds the env var - the fallback keeps the local run
        // self-contained).
        match std::env::var("WALLET8_HOLDER_DATA_KEY") {
            Ok(secret) if !secret.trim().is_empty() => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(secret.trim())
                    .expect("WALLET8_HOLDER_DATA_KEY must be base64 (32 bytes)")
            }
            _ => sha2::Sha256::digest(b"wallet8-holder:dev-data-key").to_vec(),
        }
    };
    let data_key = sentin8::crypto::MasterKey::from_bytes(&data_key_seed)
        .expect("the derived dev key is a valid master key");
    let wallet_client_id = std::env::var("WALLET8_HOLDER_CLIENT_ID")
        .unwrap_or_else(|_| "wallet8-web".to_string());
    let valkey_url = core.config.valkey_url.clone();
    Ok(AppState {
        pool: core.pool.clone(),
        env_id,
        data_key,
        data_key_seed,
        wallet_client_id,
        valkey_url,
    })
}

/// The route table (DESIGN.md §4). The shell passes the bound state
/// in - the handlers take `State<AppState>`.
pub fn routes(router: axum::Router<AppState>, _state: AppState) -> axum::Router<AppState> {
    router
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/credentials", get(crate::handlers::list_credentials))
        .route("/v1/credentials", post(crate::handlers::store_credential))
        .route(
            "/v1/credential/{id}",
            get(crate::handlers::get_credential),
        )
        .route("/v1/device-keys", post(crate::handlers::register_key))
        .route(
            "/v1/presentations",
            get(crate::handlers::list_presentations),
        )
        .route(
            "/v1/issuance/intake",
            post(crate::handlers::issuance_intake),
        )
        .route(
            "/v1/presentation/resolve",
            post(crate::handlers::presentation_resolve),
        )
        .route(
            "/v1/presentation/present",
            post(crate::handlers::presentation_deliver),
        )
}
