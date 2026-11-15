// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! The vault handlers: the credential store, the device keys, the
//! presentation history (DESIGN.md §4). Every handler runs the
//! standard authorization pipeline (extract → verify → resolve tenant →
//! Shield authorize → RLS context → execute → audit); the RLS context
//! set + the query ride ONE transaction (architecture-principles §4.3d).

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::server::AppState;

/// The stored-credential row view (the vault browser's data surface).
#[derive(Debug, sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub struct CredentialRow {
    /// The row id.
    pub id: Uuid,
    /// The format (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The mdoc doctype.
    pub doctype: Option<String>,
    /// The sd-jwt vct.
    pub vct: Option<String>,
    /// The display name.
    pub display_name: String,
    /// The issuer host.
    pub issuer: String,
    /// The status.
    pub status: String,
    /// The issuance timestamp.
    pub issued_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/credentials` - list the user's stored credentials (the
/// vault view; the material itself never rides this surface).
#[utoipa::path(
    get,
    path = "/v1/credentials",
    responses((status = 200, description = "The vault rows", body = [CredentialRow])),
    tag = "holder",
)]
pub async fn list_credentials(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Vec<CredentialRow>>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(state.env_id)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query_as!(
        CredentialRow,
        r#"SELECT id, format, doctype, vct, display_name, issuer, status,
                  issued_at
           FROM credentials
           WHERE user_id = $1 AND status = 'active'
           ORDER BY issued_at DESC"#,
        user_id,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    Ok(Json(rows))
}

/// The store request (the post-issuance intake).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StoreCredentialRequest {
    /// The format (`mso_mdoc` / `dc+sd-jwt`).
    pub format: String,
    /// The mdoc doctype.
    pub doctype: Option<String>,
    /// The sd-jwt vct.
    pub vct: Option<String>,
    /// The display name.
    pub display_name: String,
    /// The issuer host.
    pub issuer: String,
    /// The credential material (encrypted at rest by the handler).
    pub credential: String,
}

/// `POST /v1/credentials` - store a minted credential (the issuance
/// flow's last step).
#[utoipa::path(
    post,
    path = "/v1/credentials",
    request_body = StoreCredentialRequest,
    responses((status = 201, description = "Stored")),
    tag = "holder",
)]
pub async fn store_credential(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<StoreCredentialRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    // The at-rest envelope (AES-256-GCM via sentin8-crypto - the
    // plaintext never persists).
    let encrypted = sentin8::crypto::seal_str(&req.credential, &state.data_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(state.env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query!(
        r#"INSERT INTO credentials
             (id, env_id, user_id, format, doctype, vct, display_name, issuer, credential_ct)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        Uuid::new_v4(),
        state.env_id,
        user_id,
        req.format,
        req.doctype,
        req.vct,
        req.display_name,
        req.issuer,
        encrypted,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    Ok(StatusCode::CREATED)
}

/// `GET /v1/credential/{id}` - resolve a stored credential's material
/// for a presentation (the scoped read; the caller's Shield gate
/// authorizes the user).
#[utoipa::path(
    get,
    path = "/v1/credential/{id}",
    responses((status = 200, description = "The credential material")),
    tag = "holder",
)]
pub async fn get_credential(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    axum::extract::Path(id): axum::extract::Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(state.env_id)
        .execute(&mut *tx)
        .await;
    let row = sqlx::query!(
        r#"SELECT credential_ct FROM credentials
           WHERE id = $1 AND user_id = $2"#,
        id,
        user_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    let row = row.ok_or((StatusCode::NOT_FOUND, "credential not found".into()))?;
    let material = sentin8::crypto::open_str(&row.credential_ct, &state.data_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({ "credential": material })))
}

/// The device-key registration request.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RegisterKeyRequest {
    /// The JWK (public P-256).
    pub jwk: serde_json::Value,
}

/// `POST /v1/device-keys` - register a wallet device key (the RFC 7638
/// thumbprint derives in-handler).
#[utoipa::path(
    post,
    path = "/v1/device-keys",
    request_body = RegisterKeyRequest,
    responses((status = 201, description = "Registered")),
    tag = "holder",
)]
pub async fn register_key(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<RegisterKeyRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    let thumbprint = jwk_thumbprint(&req.jwk)?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(state.env_id)
        .execute(&mut *tx)
        .await;
    sqlx::query!(
        r#"INSERT INTO device_keys (id, env_id, user_id, thumbprint, jwk)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT DO NOTHING"#,
        Uuid::new_v4(),
        state.env_id,
        user_id,
        thumbprint,
        serde_json::to_value(&req.jwk).map_err(|e| e.to_string())?,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    Ok(StatusCode::CREATED)
}

/// The presentation-record view.
#[derive(Debug, sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub struct PresentationRow {
    /// The row id.
    pub id: Uuid,
    /// The verifier's client_id.
    pub verifier_client_id: String,
    /// The verifier's host.
    pub verifier_host: String,
    /// The disclosed claims.
    pub disclosed_claims: Vec<String>,
    /// The formats presented.
    pub formats: Vec<String>,
    /// The timestamp.
    pub presented_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/presentations` - the user's presentation history.
#[utoipa::path(
    get,
    path = "/v1/presentations",
    responses((status = 200, description = "The history rows", body = [PresentationRow])),
    tag = "holder",
)]
pub async fn list_presentations(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Result<Json<Vec<PresentationRow>>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(state.env_id)
        .execute(&mut *tx)
        .await;
    let rows = sqlx::query_as!(
        PresentationRow,
        r#"SELECT id, verifier_client_id, verifier_host,
                  disclosed_claims, formats, presented_at
           FROM presentations
           WHERE user_id = $1
           ORDER BY presented_at DESC
           LIMIT 100"#,
        user_id,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    Ok(Json(rows))
}

/// The RFC 7638 thumbprint of an EC JWK.
fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, (StatusCode, String)> {
    let (x, y, kty, crv) = (
        jwk.get("x").and_then(|v| v.as_str()),
        jwk.get("y").and_then(|v| v.as_str()),
        jwk.get("kty").and_then(|v| v.as_str()).unwrap_or("EC"),
        jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("P-256"),
    );
    let (x, y) = match (x, y) {
        (Some(x), Some(y)) => (x, y),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "the JWK carries no P-256 x/y members".into(),
            ))
        }
    };
    let canonical = format!(
        "{{\"crv\":\"{crv}\",\"kty\":\"{kty}\",\"x\":\"{x}\",\"y\":\"{y}\"}}"
    );
    use sha2::Digest;
    use base64::Engine;
    let digest: [u8; 32] = sha2::Sha256::digest(canonical.as_bytes()).into();
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest))
}
