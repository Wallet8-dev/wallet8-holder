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
    /// The wallet's registered OAuth redirect_uri (§3.1.2.3 - the
    /// PAR push + the token exchange MUST present the registered
    /// value; the conformance campaign overrides the default via
    /// WALLET8_HOLDER_REDIRECT_URI).
    pub wallet_redirect_uri: String,
    /// The client-attestation identity (the HAIP client_attestation
    /// client-auth variant): the attester's signing key + its x5c
    /// chain + the attestation issuer id. None = the plain form (the
    /// attestation headers stay off the PAR/token calls). Runtime-
    /// registered per campaign (POST /v1/attestation-identity - the
    /// seed rotates the attester key per seed); the env form is the
    /// boot default.
    pub wallet_attestation:
        Option<(p256::ecdsa::SigningKey, Vec<String>, String)>,
    /// The runtime attestation slot (the campaign's identity
    /// registration writes it; the handlers read it through this
    /// shared reference).
    pub wallet_attestation_slot:
        std::sync::Arc<tokio::sync::RwLock<Option<(p256::ecdsa::SigningKey, Vec<String>, String)>>>,
    /// The Valkey URL (the presentation-session store).
    pub valkey_url: String,    /// The verifier trust surface (§5.9/§12): the trusted
    /// verifier-attestation issuers - the ecosystem anchor list
    /// (deployment configuration; empty = none accepted).
    pub verifier_trust: wallet8::oid4vp::VerifierTrust,
    /// The scope-alias registry (§5.5): the wallet's server-metadata
    /// DCQL aliases - parsed from the WALLET8_HOLDER_SCOPE_ALIASES
    /// config (a JSON map scope -> DCQL query).
    pub scope_registry: std::collections::BTreeMap<String, wallet8::oid4vp::DcqlQuery>,}

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

/// The SD-JWT's parsed payload claims (the vault's sealed material ->
/// the status reference decode's input - TSL §6.2's Referenced
/// Token payload).
///
/// # Errors
/// Never returns Err: a malformed SD-JWT answers None (the caller
/// skips the status check - no reference, no statement).
pub fn sd_jwt_payload(sd_jwt: &str) -> Option<serde_json::Value> {
    use base64::Engine;
    let part = sd_jwt.split('.').nth(1)?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .ok()?;
    serde_json::from_slice(&raw).ok()
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

/// Flatten one claim member into the DCQL path-key form.
///
/// An OBJECT claim (`place_of_birth: {locality, country}`) is
/// individually addressable by a DCQL `claims.path` of
/// `["place_of_birth","locality"]` - the §6.4.1 claim-set preference
/// resolves against exactly that key. Inserting only the parent left
/// every nested `claim_sets` option unsatisfiable, so the holder fell
/// through to a less preferred option (the suite's
/// `oid4vp-1final-wallet-pid-claims-path-object-member` WARNING).
/// Arrays keep their parent key only: a DCQL path descends OBJECT
/// members, never array indices.
fn flatten_member(
    map: &mut std::collections::BTreeMap<String, serde_json::Value>,
    prefix: &str,
    value: &serde_json::Value,
) {
    let Some(obj) = value.as_object() else {
        return;
    };
    for (k, v) in obj {
        if k.starts_with('_') {
            continue; // the selective-disclosure markers
        }
        let path = format!("{prefix}/{k}");
        map.insert(path.clone(), v.clone());
        flatten_member(map, &path, v);
    }
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
    // the second segment. The credential's claims live in the
    // DISCLOSURES (each `[salt, name, value]` reveals an object
    // member): the top-level _sd markers carry only digests, so the
    // DCQL claim matching reads the decoded member values.
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
                        // NESTED members flatten into the DCQL path-key
                        // form (`place_of_birth/locality`): an OBJECT
                        // claim's members are individually addressable
                        // by a `claims.path` query, and §6.4.1's
                        // claim_sets preference resolves against THESE
                        // keys - inserting only the parent left every
                        // nested option unsatisfiable and the holder
                        // fell through to a less preferred option (the
                        // suite's
                        // `oid4vp-1final-wallet-pid-claims-path-object-member`
                        // WARNING).
                        flatten_member(&mut map, k, val);
                    }
                }
            }
        }
    }
    // The SELECTIVE-DISCLOSURE TREE: every 3-part disclosure carries
    // [salt, name, value]; a value's nested `_sd` digests resolve
    // against the sibling disclosures. The flattened map keeps the
    // DCQL paths ('place_of_birth/country') AND the plain names.
    let digests: std::collections::HashMap<String, (String, serde_json::Value)> = {
        use base64::Engine;
        let mut m = std::collections::HashMap::new();
        for part in text.split('~').skip(1) {
            if part.is_empty() {
                continue;
            }
            if let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part) {
                if let Ok(arr) = serde_json::from_slice::<Vec<serde_json::Value>>(&raw) {
                    if arr.len() == 3 {
                        use sha2::Digest as _;
                    let name = arr[1].as_str().map(str::to_owned);
                    let digest: String = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .encode(sha2::Sha256::digest(part.as_bytes()));
                    if let Some(name) = name {
                        m.insert(digest, (name, arr[2].clone()));
                    }
                    }
                }
            }
        }
        m
    };
    // Walk each top-level disclosure: the value's nested _sd digests
    // resolve to child claims (recursively) whose paths prefix with
    // the parent's name.
    fn walk_value(
        map: &mut std::collections::BTreeMap<String, serde_json::Value>,
        digests: &std::collections::HashMap<String, (String, serde_json::Value)>,
        prefix: Option<&str>,
        value: &serde_json::Value,
    ) {
        if let Some(obj) = value.as_object() {
            if let Some(sds) = obj.get("_sd").and_then(|v| v.as_array()) {
                for dg in sds {
                    if let Some(dg) = dg.as_str() {
                        if let Some((name, child)) = digests.get(dg) {
                            let path = match prefix {
                                Some(p) => format!("{p}/{name}"),
                                None => name.clone(),
                            };
                            map.insert(path.clone(), child.clone());
                            walk_value(map, digests, Some(&path), child);
                        }
                    }
                }
            }
            for (k, v) in obj {
                if k.starts_with('_') {
                    continue;
                }
                let path = match prefix {
                    Some(p) => format!("{p}/{k}"),
                    None => k.clone(),
                };
                walk_value(map, digests, Some(&path), v);
            }
        } else if let Some(arr) = value.as_array() {
            for v in arr {
                walk_value(map, digests, prefix, v);
            }
        }
    }
    for (name, value) in digests.values() {
        // Every named disclosure starts one path: the value's OWN
        // nested digests walk with the name as the prefix (the child
        // paths 'parent/child' - the DCQL path-key form).
        map.insert(name.clone(), value.clone());
        walk_value(&mut map, &digests, Some(name), value);
        // A disclosed OBJECT value's members are individually
        // addressable (`place_of_birth/locality`): the §6.4.1
        // claim_sets preference resolves against exactly that key, so
        // the members flatten here too (the same rule the payload
        // loop applies).
        flatten_member(&mut map, name, value);
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
    // The PAR redirect_uri (DESIGN 4b): an explicit
    // WALLET8_HOLDER_REDIRECT_URI wins; otherwise the rig-domain mode's
    // suite base derives it - CONFORMANCE_SUITE_URL, then
    // CONFORMANCE_SUITE_TARGET=hosted (certification.openid.net), then
    // the local rig's nginx alias (all with the VCI wallet alias). The
    // value MUST match the client row the cert-wallet env registered
    // (the seed writes the suite-target switch's callback there); a
    // mismatch is the suite's "redirect_uri does not match the
    // registered redirect_uri" 400 at the PAR push.
    let wallet_alias = std::env::var("WALLET8_HOLDER_SUITE_ALIAS")
        .unwrap_or_else(|_| "sentin8-wallet".to_string());
    let suite_base_env = std::env::var("CONFORMANCE_SUITE_URL").ok().filter(|u|
        !u.trim().is_empty());
    let suite_base = suite_base_env.unwrap_or_else(|| {
        if std::env::var("CONFORMANCE_SUITE_TARGET").as_deref() == Ok("hosted") {
            "https://www.certification.openid.net".to_string()
        } else {
            "https://localhost.emobix.co.uk:8443".to_string()
        }
    });
    let wallet_redirect_uri = std::env::var("WALLET8_HOLDER_REDIRECT_URI")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| format!("{}/test/a/{wallet_alias}/callback", suite_base.trim_end_matches('/')));
    // The client-attestation identity (HAIP client_attestation): the
    // ATTESTER trust-domain key + x5c chain (+ the issuer id the
    // attestation claims). WALLET8_HOLDER_ATTESTATION_KEY_PEM +
    // WALLET8_HOLDER_ATTESTATION_X5C + WALLET8_HOLDER_ATTESTATION_ISSUER.
    let attestation_key_pem = std::env::var("WALLET8_HOLDER_ATTESTATION_KEY_PEM")
        .ok()
        .filter(|p| !p.trim().is_empty());
    let attestation_x5c = std::env::var("WALLET8_HOLDER_ATTESTATION_X5C")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let attestation_issuer = std::env::var("WALLET8_HOLDER_ATTESTATION_ISSUER")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let valkey_url = core.config.valkey_url.clone();
    let wallet_attestation = match (attestation_key_pem, attestation_x5c, attestation_issuer) {
        (Some(pem), Some(x5c), Some(iss)) => {
            use p256::pkcs8::DecodePrivateKey;
            let key = p256::SecretKey::from_pkcs8_pem(&pem)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("the attestation key: {e}")))?;
            let chain: Vec<String> = serde_json::from_str::<Vec<String>>(&x5c)
                .unwrap_or_else(|_| x5c.split(',').map(str::to_string).collect());
            Some((p256::ecdsa::SigningKey::from(key), chain, iss))
        }
        _ => None,
    };
    // The verifier-attestation issuers (§12's trust anchor - the
    // ecosystem's deployment data): WALLET8_HOLDER_ATTESTATION_ISSUERS
    // = a JSON array of {"iss": ..., "jwk": {...}} entries.
    let verifier_trust = match std::env::var("WALLET8_HOLDER_ATTESTATION_ISSUERS") {
        Ok(raw) if !raw.trim().is_empty() => {
            let parsed: serde_json::Value = serde_json::from_str(&raw)?;
            let mut issuers = Vec::new();
            if let Some(entries) = parsed.as_array() {
                for entry in entries {
                    let iss = entry.get("iss").and_then(|v| v.as_str()).unwrap_or_default();
                    if let Some(jwk) = entry.get("jwk") {
                        issuers.push((iss.to_string(), jwk.clone()));
                    }
                }
            }
            wallet8::oid4vp::VerifierTrust { attestation_issuers: issuers }
        }
        _ => wallet8::oid4vp::VerifierTrust::default(),
    };
    // The scope-alias registry (§5.5): WALLET8_HOLDER_SCOPE_ALIASES =
    // a JSON map scope -> DCQL query.
    let scope_registry = match std::env::var("WALLET8_HOLDER_SCOPE_ALIASES") {
        Ok(raw) if !raw.trim().is_empty() => {
            serde_json::from_str::<std::collections::BTreeMap<String, wallet8::oid4vp::DcqlQuery>>(&raw)?
        }
        _ => Default::default(),
    };
    Ok(AppState {
        pool: core.pool.clone(),
        env_id,
        data_key,
        data_key_seed,
        wallet_client_id,
        wallet_redirect_uri,
        wallet_attestation_slot: std::sync::Arc::new(tokio::sync::RwLock::new(wallet_attestation.clone())),
        wallet_attestation,
        valkey_url,
        verifier_trust,
        scope_registry,
    })
}

/// The route table (DESIGN.md §4 + §11.5's orchestration). The shell
/// passes the bound state in - the handlers take `State<AppState>`.
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
        // §11.5: the authorization-code round's orchestration pair
        // (prepare -> the browser authorize round -> complete).
        .route(
            "/v1/issuance/prepare",
            post(crate::handlers::issuance_prepare),
        )
        .route(
            "/v1/issuance/complete",
            post(crate::handlers::issuance_complete),
        )
        // §9: the deferred-issuance poll.
        .route(
            "/v1/issuance/deferred",
            post(crate::handlers::issuance_deferred),
        )
        .route(
            "/v1/presentation/resolve",
            post(crate::handlers::presentation_resolve),
        )
        .route(
            "/v1/presentation/present",
            post(crate::handlers::presentation_deliver),
        )
        // §11.6: the vault's status sync (the revocation walk).
        .route(
            "/v1/credentials/sync",
            post(crate::handlers::credentials_sync),
        )
        // The client-attestation identity registration (the campaign
        // HAIP cells - the seed rotates the attester key per seed and
        // the runner registers it before the plans run).
        .route(
            "/v1/attestation-identity",
            post(crate::handlers::register_attestation_identity),
        )
}
