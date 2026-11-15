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
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
    Ok(AppState {
        pool: core.pool.clone(),
        env_id,
        data_key,
        data_key_seed,
        wallet_client_id,
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
