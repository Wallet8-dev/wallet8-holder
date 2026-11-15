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
    pub data_key: Vec<u8>,
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
    let data_key = sentin8::crypto::derive_data_key(
        core.config
            .service_secret("WALLET8_HOLDER_DATA_KEY")
            .as_deref()
            .unwrap_or_default(),
    );
    Ok(AppState {
        pool: core.pool.clone(),
        env_id,
        data_key,
    })
}

/// The route table (DESIGN.md §4).
pub fn routes(router: axum::Router) -> axum::Router {
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
}
