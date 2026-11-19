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
           FROM holder.credentials
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
    let encrypted = sentin8::crypto::seal(&state.data_key, req.credential.as_bytes())
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
        r#"INSERT INTO holder.credentials
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
        r#"SELECT credential_ct FROM holder.credentials
           WHERE id = $1 AND user_id = $2"#,
        id,
        user_id,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    let row = row.ok_or((StatusCode::NOT_FOUND, "credential not found".into()))?;
    let material = sentin8::crypto::open_str(&state.data_key, &row.credential_ct)
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
    let jwk_value = serde_json::to_value(&req.jwk)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    sqlx::query!(
        r#"INSERT INTO holder.device_keys (id, env_id, user_id, thumbprint, jwk)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT DO NOTHING"#,
        Uuid::new_v4(),
        state.env_id,
        user_id,
        thumbprint,
        jwk_value,
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
           FROM holder.presentations
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

// ── The wallet-role orchestration (DESIGN.md §2b) ────────────────────

/// The offer-intake request (the app's `/v1/issuance/intake`).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct IntakeRequest {
    /// The scanned offer URL (the issuer's credential-offer landing).
    pub offer_url: String,
    /// The End-User's Transaction Code (§4.1.1 - REQUIRED when the
    /// offer's grants carry a tx_code object; the §13.6.1 replay
    /// defense).
    #[serde(default)]
    pub tx_code: Option<String>,
}

/// `POST /v1/issuance/intake` - the full issuance flow (the wallet's
/// offer intake): resolve the offer, the authorize round (PAR + code
/// exchange or the pre-authorized code), the nonce + proof +
/// credential request, the vault store. The Rust SDK's OID4VCI
/// driver runs the protocol; this endpoint orchestrates + stores.
#[utoipa::path(
    post,
    path = "/v1/issuance/intake",
    request_body = IntakeRequest,
    responses((status = 200, description = "The stored credential view")),
    tag = "holder",
)]
pub async fn issuance_intake(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<IntakeRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    let http = state.http_client();
    // (1) The offer intake (OID4VCI 4.1.2/4.1.3): the scanned URL
    // carries the offer by value (credential_offer) or by reference
    // (credential_offer_uri - a plain https fetch, 4.1.3).
    let offer_body = match wallet8::oid4vci::parse_offer_url(&req.offer_url)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    {
        wallet8::oid4vci::OfferIntake::ByValue(v) => v,
        wallet8::oid4vci::OfferIntake::ByReference(uri) => http
            .get(&uri)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("offer fetch: {e}")))?
            .text()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("offer read: {e}")))?,
    };
    let offer = wallet8::oid4vci::parse_credential_offer(&offer_body)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // (2) The issuer metadata (12.2.2) + the first offered
    // configuration; the AS selection honors the offer's hint
    // (12.2.4: an unknown hint MUST NOT proceed).
    let metadata = wallet8::oid4vci::resolve_issuer_metadata(&http, &offer.credential_issuer)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let config_id = offer
        .credential_configuration_ids
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "the offer lists no configurations (4.1.1)".into()))?
        .clone();
    let configuration = metadata
        .credential_configurations_supported
        .get(&config_id)
        .ok_or((
            StatusCode::BAD_REQUEST,
            "the offered configuration is unknown to the issuer (4.1.1)".into(),
        ))?;
    // (3) The pre-authorized grant (3.5 + 6.1): the anonymous form
    //     drops the client_id when the AS advertises
    //     pre_authorized_grant_anonymous_access_supported (12.3); a
    //     present tx_code object makes the value REQUIRED (4.1.1).
    //     The authorization-code variant performs the PAR round (the
    //     app drives the browser; the deferred orchestration
    //     endpoint carries the code home).
    let grant = offer
        .grants
        .iter()
        .find_map(|g| match g {
            wallet8::oid4vci::OfferGrant::PreAuthorizedCode {
                pre_authorized_code,
                tx_code,
                authorization_server,
            } => Some((pre_authorized_code.clone(), tx_code.clone(), authorization_server.clone())),
            _ => None,
        })
        .ok_or((
            StatusCode::NOT_IMPLEMENTED,
            "the authorization-code intake lands with the prepare/complete \
             orchestration pair (the /v1/issuance/prepare endpoint)"
                .into(),
        ))?;
    let as_identifier = wallet8::oid4vci::select_authorization_server(
        &metadata,
        grant.2.as_deref(),
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let as_metadata =
        wallet8::oid4vci::resolve_as_metadata(&http, &as_identifier)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let anonymous = as_metadata.pre_authorized_grant_anonymous_access_supported;
    let client_id: Option<&str> = if anonymous {
        None
    } else {
        Some(state.wallet_client_id.as_str())
    };
    // The tx_code VALUE comes from the End-User (§4.1.1: a present
    // tx_code object makes the token request's tx_code REQUIRED -
    // §6.3 answers invalid_request when it is missing; the §13.6.1
    // replay defense demands the End-User channel).
    let tx_code_value: Option<String> = match &grant.1 {
        Some(_requirements) => {
            let value = req.tx_code.clone().filter(|v| !v.trim().is_empty()).ok_or((
                StatusCode::BAD_REQUEST,
                "the offer demands a tx_code (4.1.1) - the End-User's \
                 Transaction Code is REQUIRED for this intake"
                    .into(),
            ))?;
            Some(value)
        }
        None => None,
    };
    let access_token = {
        let token = wallet8::oid4vci::exchange_pre_authorized(
            &http,
            &as_metadata.token_endpoint,
            client_id,
            &grant.0,
            tx_code_value.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
        token
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or((StatusCode::BAD_GATEWAY, "the token response carries no access_token (6.2)".into()))?
            .to_string()
    };
    // (4) The nonce pre-flight (7.1: a nonce_endpoint present makes
    //     the proof's nonce REQUIRED, 8.2) + the proof (F.1: iss
    //     omitted for the anonymous form) + the credential request
    //     (8.2: credential_identifier when the token response carried
    //     authorization_details, else the configuration id).
    let device_key = state.device_key(&user_id).await?;
    let c_nonce = match &metadata.nonce_endpoint {
        Some(endpoint) => Some(
            wallet8::oid4vci::fetch_nonce(&http, endpoint)
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?,
        ),
        None => None,
    };
    let proof = wallet8::oid4vci::mint_jwt_proof(
        &device_key,
        client_id,
        &offer.credential_issuer,
        c_nonce.as_deref(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // The target defaults to the configuration id (8.2); the
    // credential_identifiers form lands with the authorization-code
    // round (the token response's authorization_details ride that
    // exchange, 6.2).
    let target = wallet8::oid4vci::CredentialRequestTarget::ConfigurationId(config_id.clone());
    // The response-encryption material (8.2) - mint when the
    // configuration advertises alg/enc; the JWE answer is opened with
    // the ephemeral key.
    // The encryption block rides the METADATA TOP LEVEL (draft 16
    // moved credential_response_encryption out of the configuration).
    let enc_block = metadata.credential_response_encryption.as_ref();
    let alg_ok = enc_block
        .and_then(|e| e.get("alg_values_supported"))
        .and_then(|a| a.as_array())
        .map(|a| a.iter().any(|v| v.as_str() == Some("ECDH-ES")))
        .unwrap_or(false);
    let enc_pick: Option<(&'static str, &'static str)> = if alg_ok {
        Some((
            "ECDH-ES",
            enc_block
                .and_then(|e| e.get("enc_values_supported"))
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    ["A256GCM", "A128GCM", "A256CBC-HS512", "A128CBC-HS256"]
                        .iter()
                        .find(|c| arr.iter().any(|v| v.as_str() == Some(**c)))
                        .copied()
                })
                .unwrap_or("A256GCM"),
        ))
    } else {
        None
    };
    let response_encryption =
        enc_pick.map(|(alg, enc)| (wallet8::oid4vci::mint_response_encryption(), alg, enc));
    let req_body = wallet8::oid4vci::CredentialRequestBody {
        target,
        proofs: serde_json::json!({ "jwt": [proof] }),
        credential_response_encryption: response_encryption.as_ref().map(|(m, alg, enc)| {
            serde_json::json!({ "jwk": m.jwk, "alg": alg, "enc": enc })
        }),
    };
    let response = wallet8::oid4vci::request_credential(
        &http,
        &metadata.credential_endpoint,
        &access_token,
        &req_body,
        response_encryption.as_ref().map(|(m, _, _)| m),
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    // (5) The vault store (8.3: the immediate form stores; the
    //     deferred form records the transaction for the 9 poll; the
    //     11 notification rides the notification_id).
    // §8.3/§11: the immediate form carries the optional
    // notification_id; the deferred form parks it (below).
    let (minted, notification_id) = match response {
        wallet8::oid4vci::CredentialResponse::Issued { credentials, notification_id } => {
            let minted = credentials
                .first()
                .ok_or((StatusCode::BAD_GATEWAY, "no credentials minted (8.3)".into()))?
                .clone();
            (minted, notification_id)
        }
        // §9: the deferred form parks the transaction - the app
        // polls /v1/issuance/deferred after `interval`.
        wallet8::oid4vci::CredentialResponse::Deferred { transaction_id, interval, notification_id } => {
            let deferred_session = format!("holder:vci:deferred:{transaction_id}");
            {
                use glide::AsyncCommands as _;
                let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                let parked = serde_json::json!({
                    "credential_issuer": offer.credential_issuer,
                    "credential_endpoint": metadata.credential_endpoint,
                    "deferred_credential_endpoint": metadata.deferred_credential_endpoint,
                    "notification_endpoint": metadata.notification_endpoint,
                    "notification_id": notification_id,
                    "config_id": config_id,
                    "format": configuration.get("format").and_then(|f| f.as_str()).unwrap_or("mso_mdoc"),
                    "doctype": configuration.get("doctype").and_then(|d| d.as_str()),
                    "vct": configuration.get("vct").and_then(|v| v.as_str()),
                    "access_token": access_token,
                });
                let set_result: Result<String, glide::GlideError> = conn
                    .set_ex(deferred_session.clone(), parked.to_string(), 86400u64)
                    .await;
                if let Err(e) = set_result {
                    tracing::error!(error = %e, key = %deferred_session,
                        "the deferred park write FAILED - the deferred poll will 404");
                }
            }
            return Ok(Json(serde_json::json!({
                "status": "deferred",
                "transaction_id": transaction_id,
                "interval": interval,
            })));
        }
    };
    let format = configuration
        .get("format")
        .and_then(|f| f.as_str())
        .unwrap_or("mso_mdoc")
        .to_string();
    let doctype = configuration.get("doctype").and_then(|d| d.as_str());
    let vct = configuration.get("vct").and_then(|v| v.as_str());
    let sealed = sentin8::crypto::seal(&state.data_key, minted.credential.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row_id = Uuid::new_v4();
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
        r#"INSERT INTO holder.credentials
             (id, env_id, user_id, format, doctype, vct, display_name, issuer, credential_ct)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (env_id, user_id) DO UPDATE
             SET format = EXCLUDED.format,
                 doctype = EXCLUDED.doctype,
                 vct = EXCLUDED.vct,
                 display_name = EXCLUDED.display_name,
                 issuer = EXCLUDED.issuer,
                 credential_ct = EXCLUDED.credential_ct,
                 issued_at = now()"#,
        row_id,
        state.env_id,
        user_id,
        format,
        doctype,
        vct,
        config_id,
        offer.credential_issuer,
        sealed,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    // §11: the notification rides the response's notification_id -
    // the issuer's status surface (credential_accepted, 11.1; the
    // issuer treats notifications as idempotent).
    if let (Some(endpoint), Some(notification_id)) =
        (metadata.notification_endpoint.as_deref(), notification_id.as_deref())
    {
        // The §11 notification through the DPoP session (the resource
        // endpoint's own nonce challenge applies, DESIGN 4b).
        let device_key = state.device_key(&user_id).await?;
        let mut dpop = wallet8::oid4vci::DpopSession::new(device_key);
        let notify_body = serde_json::json!({
            "notification_id": notification_id,
            "event": wallet8::oid4vci::NotificationEvent::CredentialAccepted.code(),
        });
        let _ = dpop
            .post_protected_notify(&http, endpoint, &access_token, &notify_body)
            .await;
    }
    Ok(Json(serde_json::json!({
        "id": row_id,
        "format": format,
        "display_name": config_id,
        "doctype": doctype,
        "vct": vct,
        "issuer": offer.credential_issuer,
    })))
}

/// The presentation-resolve request (the app's consent preview).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ResolveRequest {
    /// The scanned verifier request_uri.
    pub request_uri: String,
    /// The platform-asserted origin (the DC API channel - App. A.2);
    /// None on the redirect channels.
    #[serde(default)]
    pub origin: Option<String>,
}

/// `POST /v1/presentation/resolve` - the pre-consent preview: parse
/// the verifier's request object, match the DCQL query against the
/// vault, and return the requested claims + the verifier identity
/// (the consent screen; a malformed/unsafe request answers the
/// error - the app renders the error screen).
///
/// The §5.9 verification runs BEFORE the shape gate (§15.8 - a bad
/// signature never reaches the DCQL or the consent screen); the
/// scope alias resolves against the registry (§5.5); the
/// expected_origins check runs on the DC API channel (App. A.2).
#[utoipa::path(
    post,
    path = "/v1/presentation/resolve",
    request_body = ResolveRequest,
    responses((status = 200, description = "The consent preview")),
    tag = "holder",
)]
pub async fn presentation_resolve(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<ResolveRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    // The request-object fetch (5.4 option 3 / RFC 9101: the
    // request_uri serves the request object).
    let http = state.http_client();
    let object = http
        .get(&req.request_uri)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("request object fetch: {e}")))?
        .text()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("request object read: {e}")))?;
    // §5.9 + §15.8: the signature + the per-prefix rules verify
    // FIRST - fail-closed, the visible error the app renders.
    let request = wallet8::oid4vp::verify_request_object(&object, &state.verifier_trust)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{}: {}", e.code, e.description)))?;
    // The shape gate (§5.1/5.2 - includes the transaction_data
    // rejection §8.4).
    wallet8::oid4vp::check_request_shape(&request)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // The DC API origin check (App. A.2).
    wallet8::oid4vp::check_expected_origins(&request, req.origin.as_deref())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // The scope alias resolution (§5.5) - a scope request maps to
    // the DCQL query the registry defines.
    let request = wallet8::oid4vp::resolve_scope_alias(&request, &state.scope_registry)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let query = request
        .dcql_query
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "the request carries no dcql_query (5.1)".into()))?;
    // The vault snapshot (the user's holdings) - the sealed rows open
    // for the DCQL evaluation (6.4).
    let holdings = state.user_holdings(&user_id).await?;
    let matches = wallet8::oid4vp::evaluate_dcql(query, &holdings)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    // The consent preview (6.4.3: what the wallet shows the user).
    let preview: Vec<serde_json::Value> = matches
        .iter()
        .map(|m| {
            serde_json::json!({
                "query_id": m.query.id,
                "format": m.credential.format,
                "doctype": m.credential.doctype,
                "vct": m.credential.vct,
                "claims": m.selected_claim_paths.iter().map(|p| wallet8::oid4vp::claim_path_display(p)).collect::<Vec<_>>(),
                "verifier": request.client_id,
                "require_cryptographic_holder_binding": m.query.require_cryptographic_holder_binding,
            })
        })
        .collect();
    // The resolved request rides the session alias (the present step
    // re-reads it; the app never re-fetches the verifier).
    let session_key = format!("holder:vp:req:{}", uuid::Uuid::new_v4());
    {
        use glide::AsyncCommands as _;
        let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let payload = serde_json::to_string(&request)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _: Result<(), _> = conn
            .set_ex(&session_key, payload, 600u64)
            .await;
    }
    let host = request
        .response_uri
        .as_deref()
        .or(request.redirect_uri.as_deref())
        .and_then(|u| url_host(u))
        .unwrap_or("");
    Ok(Json(serde_json::json!({
        "session": session_key,
        "verifier_client_id": request.client_id,
        "verifier_host": host,
        "response_mode": request.response_mode.clone().unwrap_or_else(|| "direct_post".into()),
        "nonce": request.nonce,
        "credentials": preview,
    })))
}

/// The URL's host member (the preview's display form).
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    rest.split('/').next()
}

/// The presentation-deliver request (the post-consent flow).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PresentRequest {
    /// The resolve step's session key.
    pub session: String,
    /// The user's consent decision.
    pub approved: bool,
    /// The platform-asserted origin (the DC API channel - App. A.4;
    /// None on the redirect channels).
    #[serde(default)]
    pub origin: Option<String>,
}

/// `POST /v1/presentation/present` - the post-consent delivery: the
/// vp_token assembly (the mdoc DeviceResponse / the sd-jwt + KB) and
/// the direct_post/dc_api submission; the history record rides the
/// same transaction. A denied/unsatisfiable request answers the
/// prescribed error - never an empty vp_token.
///
/// The delivery channel follows the response_mode: `direct_post` /
/// `direct_post.jwt` (§8.2/§8.3.1 - the .jwt form posts
/// `response=<JWE>`), or `dc_api`/`dc_api.jwt` (App. A.4 - the
/// response returns to the caller's promise, no back-channel).
#[utoipa::path(
    post,
    path = "/v1/presentation/present",
    request_body = PresentRequest,
    responses((status = 200, description = "The presentation outcome")),
    tag = "holder",
)]
pub async fn presentation_deliver(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<PresentRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    // The resolve step's session (the resolved request object).
    use glide::AsyncCommands as _;
    let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let payload: Option<String> = conn
        // The same full-key-form session rule (the oid4vp parking).
        .get(if req.session.starts_with("holder:") {
            req.session.clone()
        } else {
            format!("holder:vp:req:{}", req.session.trim_start_matches("vp:req:"))
        })
        .await
        .ok()
        .flatten();
    let payload = payload
        .ok_or((StatusCode::NOT_FOUND, "the presentation session expired".into()))?;
    let request: wallet8::oid4vp::AuthorizationRequest = serde_json::from_str(&payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("the session request parse: {e}")))?;
    // The consent gate (15.1: explicit consent before any release).
    if !req.approved {
        return Ok(Json(wallet8::oid4vp::error_response(
            wallet8::oid4vp::WalletError::AccessDenied,
            "the user declined to share the requested credentials (8.5)",
            request.state.as_deref(),
        )));
    }
    // The re-gate on the deliver step (the session is the source of
    // truth; the shape + origin checks run again).
    wallet8::oid4vp::check_request_shape(&request)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    wallet8::oid4vp::check_expected_origins(&request, req.origin.as_deref())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let request = wallet8::oid4vp::resolve_scope_alias(&request, &state.scope_registry)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let dcql = request
        .dcql_query
        .as_ref()
        .ok_or((StatusCode::BAD_REQUEST, "the request carries no dcql_query (5.1)".into()))?;
    // The holdings + the 6.4 evaluation + the 8.1 assembly (the mdoc
    // DeviceResponse over the B.2.6 transcripts; the sd-jwt + KB).
    let holdings = state.user_holdings(&user_id).await?;
    let matches = wallet8::oid4vp::evaluate_dcql(dcql, &holdings)
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e))?;
    let device_key = state.device_key(&user_id).await?;
    let vp_token = wallet8::oid4vp::build_vp_token(&matches, &device_key, &request, req.origin.as_deref())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // The delivery per the response_mode (§8.2/§8.3.1/App. A.4).
    let mode = request.response_mode.as_deref().unwrap_or("direct_post");
    let (outcome, response_json) = match mode {
        // App. A.4: the response rides the promise - the app
        // resolves it; NO back-channel post.
        "dc_api" => {
            let response = wallet8::oid4vp::dc_api_response(&vp_token, request.state.as_deref(), None)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            (None, response)
        }
        "dc_api.jwt" => {
            let response = wallet8::oid4vp::dc_api_response(
                &vp_token,
                request.state.as_deref(),
                Some(&request.client_metadata),
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
            (None, response)
        }
        // §8.3.1: the encrypted form posts response=<JWE>.
        "direct_post.jwt" => {
            let response_uri = request.response_uri.clone().ok_or((
                StatusCode::BAD_REQUEST,
                "the request carries no response_uri (8.2)".into(),
            ))?;
            let http = state.http_client();
            let result = wallet8::oid4vp::post_response_encrypted(
                &http,
                &response_uri,
                &vp_token,
                request.state.as_deref(),
                &request.client_metadata,
            )
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
            (Some(result.redirect_uri), serde_json::json!({"status": "presented"}))
        }
        // §8.2: the plain form posts vp_token=.
        _ => {
            let response_uri = request
                .response_uri
                .clone()
                .ok_or((StatusCode::BAD_REQUEST, "the request carries no response_uri (8.2)".into()))?;
            let http = state.http_client();
            let result = wallet8::oid4vp::post_response(
                &http,
                &response_uri,
                &vp_token,
                request.state.as_deref(),
            )
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
            (Some(result.redirect_uri), serde_json::json!({"status": "presented"}))
        }
    };
    // The history record (the same transaction).
    let disclosed: Vec<String> = matches
        .iter()
        .map(|m| m.query.id.clone())
        .collect();
    let formats: Vec<String> = matches
        .iter()
        .map(|m| m.credential.format.clone())
        .collect();
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
        r#"INSERT INTO holder.presentations
             (id, env_id, user_id, verifier_client_id, verifier_host,
              disclosed_claims, formats)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        Uuid::new_v4(),
        state.env_id,
        user_id,
        request.client_id,
        request
            .response_uri
            .clone()
            .or(request.redirect_uri.clone())
            .unwrap_or_default(),
        &disclosed,
        &formats,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    let mut out = serde_json::json!({
        "status": "presented",
        "presented": matches.iter().map(|m| m.query.id.clone()).collect::<Vec<_>>(),
    });
    if let Some(redirect) = outcome.flatten() {
        out["redirect_url"] = serde_json::json!(redirect);
    }
    // The DC API forms merge the promise payload.
    if mode == "dc_api" || mode == "dc_api.jwt" {
        out = response_json;
    }
    Ok(Json(out))
}

// ── The authorization-code orchestration (§3.4 + §11.5) ──────────────

/// The prepare request (the offer intake -> the authorize URL).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PrepareRequest {
    /// The scanned offer URL.
    pub offer_url: String,
    /// The issuer-metadata URL override (the conformance campaign's
    /// RFC8414 form - the suite hosts `{base}/.well-known/...` where base
    /// carries the instance path; the §12.2.2 OIDC-suffix derivation is
    /// rejected by the suite's path-form check).
    #[serde(default)]
    pub issuer_metadata_url: Option<String>,
    /// The AS-metadata URL override (the same campaign rule - RFC 8414).
    #[serde(default)]
    pub as_metadata_url: Option<String>,
}

/// The complete request (the browser callback -> the credential).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CompleteRequest {
    /// The prepare step's session key.
    pub session: String,
    /// The authorization response's code.
    pub code: String,
    /// The authorization response's state (MUST match the pushed
    /// state - §5.2's CSRF defense).
    pub state: String,
}

/// `POST /v1/issuance/prepare` - the authorization-code round's first
/// half (§3.4/§5.1.4): parse the offer, resolve the metadata, push
/// the PAR (with `authorization_details` type `openid_credential`
/// §5.1.1), and return the authorize URL - the app opens the
/// browser round. The session (offer + metadata + PKCE + state)
/// parks in Valkey keyed by the session id.
#[utoipa::path(
    post,
    path = "/v1/issuance/prepare",
    request_body = PrepareRequest,
    responses((status = 200, description = "The authorize URL + the session")),
    tag = "holder",
)]
pub async fn issuance_prepare(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<PrepareRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    let http = state.http_client();
    // (1) The offer (4.1.2/4.1.3).
    let offer_body = match wallet8::oid4vci::parse_offer_url(&req.offer_url)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    {
        wallet8::oid4vci::OfferIntake::ByValue(v) => v,
        wallet8::oid4vci::OfferIntake::ByReference(uri) => http
            .get(&uri)
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("offer fetch: {e}")))?
            .text()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("offer read: {e}")))?,
    };
    let offer = wallet8::oid4vci::parse_credential_offer(&offer_body)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // (2) The metadata (12.2.2) + the offered configuration. The
    // campaign override fetches the EXPLICIT metadata URL (the mock
    // issuer's RFC8414 path form).
    let metadata = match &req.issuer_metadata_url {
        Some(url) => wallet8::oid4vci::fetch_issuer_metadata(&http, url, &offer.credential_issuer).await,
        None => wallet8::oid4vci::resolve_issuer_metadata(&http, &offer.credential_issuer).await,
    }
    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let config_id = offer
        .credential_configuration_ids
        .first()
        .ok_or((StatusCode::BAD_REQUEST, "the offer lists no configurations (4.1.1)".into()))?
        .clone();
    // The authorization-server selection: the authorization_code
    // grant's hint or the metadata's list (12.2.4).
    let hint = offer.grants.iter().find_map(|g| match g {
        wallet8::oid4vci::OfferGrant::AuthorizationCode { issuer_state: _, authorization_server } => {
            authorization_server.clone()
        }
        _ => None,
    });
    let as_identifier = wallet8::oid4vci::select_authorization_server(&metadata, hint.as_deref())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let as_metadata = match &req.as_metadata_url {
        Some(url) => wallet8::oid4vci::fetch_as_metadata(&http, url).await,
        None => wallet8::oid4vci::resolve_as_metadata(&http, &as_identifier).await,
    }
    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let par_endpoint = as_metadata
        .pushed_authorization_request_endpoint
        .clone()
        .ok_or((StatusCode::NOT_IMPLEMENTED, "the AS advertises no PAR endpoint (5.1.4/9126)".into()))?;
    // (3) The PAR push (5.1.4) - the authorization_details form
    // (5.1.1) with the locations member when the metadata lists
    // multiple authorization_servers.
    let locations = if metadata.authorization_servers.len() > 1 {
        Some(offer.credential_issuer.as_str())
    } else {
        None
    };
    let details = wallet8::oid4vci::authorization_details(&config_id, locations, None);
    let issuer_state = offer.grants.iter().find_map(|g| match g {
        wallet8::oid4vci::OfferGrant::AuthorizationCode { issuer_state, .. } => {
            issuer_state.clone()
        }
        _ => None,
    });
    // The RFC 7523 private_key_jwt client assertion (the mock issuer's
    // PAR endpoint validates the client auth; the plan's
    // client_auth_type=private_key_jwt posture).
    let device_key = state.device_key(&user_id).await?;
    let client_assertion = wallet8::oid4vci::mint_client_assertion(
        &device_key,
        &state.wallet_client_id,
        &as_identifier,
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // The PAR scope (§5.1.2): the offered configuration's scope when
    // the metadata declares one (the conformance mock's
    // `eudi.pid.1`), else none (the suite rejects `openid` under
    // this plan's PLAIN_OAUTH variant).
    let config_scope = metadata
        .credential_configurations_supported
        .get(&config_id)
        .and_then(|c| c.get("scope"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // The client attestation (the HAIP client_attestation client-auth):
    // the pair rides the PAR push headers when the holder carries the
    // attester identity (DESIGN 4b; the campaign's HAIP variant).
    // The AS may advertise a challenge_endpoint (HAIP): a fresh
    // challenge is fetched per endpoint and echoed in the PoP claim.
    let challenge = match as_metadata.challenge_endpoint.as_deref() {
        Some(ce) => match wallet8::oid4vci::fetch_attestation_challenge(&http, ce).await {
            Ok(c) => Some(c),
            Err(e) => return Err((StatusCode::BAD_GATEWAY, format!("haip challenge: {e}"))),
        },
        None => None,
    };
    let wallet_attestation = state
        .wallet_attestation_slot
        .read()
        .await
        .as_ref()
        .map(|(attester, chain, issuer)| {
            wallet8::oid4vci::mint_client_attestation(
                attester,
                chain,
                issuer,
                &state.wallet_client_id,
                &device_key,
                // The PoP aud = the AS identifier itself (the suite
                // validates against the exact issuer string, trailing
                // slash included - HAIP-4.4.1).
                &as_identifier,
                // The HAIP challenge: when the AS advertises a
                // challenge_endpoint, GET a fresh challenge and echo
                // it in the PoP 'challenge' claim.
                challenge.as_deref(),
                600,
            )
        })
        .transpose()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let (_request_uri, oauth_state, pkce) = wallet8::oid4vci::push_authorization_request(
        &http,
        &par_endpoint,
        &state.wallet_client_id,
        &state.wallet_redirect_uri,
        &details,
        issuer_state.as_deref(),
        Some(&client_assertion),
        config_scope.as_deref(),
        wallet_attestation.as_ref(),
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    // (4) The session parks (600s - the PAR expiry window).
    // The key rides the workload ACL namespace (`~holder:*`, the
    // sentin8 valkey ACL policy for `m2m-wallet8:holder`) - `vci:*`
    // is writable by no workload.
    let session = format!("holder:vci:prepare:{}", uuid::Uuid::new_v4());
    {
        use glide::AsyncCommands as _;
        let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let parked = serde_json::json!({
            "user_id": user_id.to_string(),
            "offer": offer_body,
            "credential_issuer": offer.credential_issuer,
            "config_id": config_id,
            "as_metadata": as_metadata,
            "as_identifier": as_identifier,
            "metadata": metadata,
            "pkce_verifier": pkce.verifier,
            "oauth_state": oauth_state,
        });
        let _: Result<(), _> = conn
            .set_ex(&session, parked.to_string(), 600u64)
            .await;
    }
    // (5) The authorize URL (9126 §5: client_id + request_uri only).
    let authorize_url = wallet8::oid4vci::par_authorize_url(
        &as_metadata.authorization_endpoint,
        &state.wallet_client_id,
        &_request_uri,
    );
    Ok(Json(serde_json::json!({
        "session": session,
        "authorize_url": authorize_url,
    })))
}

/// `POST /v1/issuance/complete` - the authorization-code round's
/// second half (§3.4): verify the state, exchange the code (PKCE),
/// fetch the nonce, mint the proof, request the credential, store,
/// and send the notification (§11) on the notification_id.
#[utoipa::path(
    post,
    path = "/v1/issuance/complete",
    request_body = CompleteRequest,
    responses((status = 200, description = "The stored credential view")),
    tag = "holder",
)]
pub async fn issuance_complete(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<CompleteRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _ = crate::server::caller_user_id(&query).await?;
    use glide::AsyncCommands as _;
    let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let parked_raw: Option<String> = conn
        // The session id travels in full-key form
        // (`holder:vci:prepare:<uuid>`) - read exactly that key; only a
        // legacy bare-uuid id gets the template reapplied.
        .get(if req.session.starts_with("holder:") {
            req.session.clone()
        } else {
            format!("holder:vci:prepare:{}", req.session.trim_start_matches("vci:prepare:"))
        })
        .await
        .ok()
        .flatten();
    let parked_raw = parked_raw
        .ok_or((StatusCode::NOT_FOUND, "the issuance session expired".into()))?;
    let parked: serde_json::Value = serde_json::from_str(&parked_raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("the session parse: {e}")))?;
    // The state check (5.2's CSRF defense - the pushed state MUST
    // match the callback's).
    let expected_state = parked.get("oauth_state").and_then(|v| v.as_str()).unwrap_or("");
    if expected_state != req.state {
        return Err((StatusCode::BAD_REQUEST, "the state does not match the pushed authorization request (5.2)".into()));
    }
    let user_id = Uuid::parse_str(parked.get("user_id").and_then(|v| v.as_str()).unwrap_or_default())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("the session user: {e}")))?;
    let credential_issuer = parked
        .get("credential_issuer")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let config_id = parked
        .get("config_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let metadata: wallet8::oid4vci::IssuerMetadata =
        serde_json::from_value(parked.get("metadata").cloned().unwrap_or_default())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("the session metadata: {e}")))?;
    let as_metadata: wallet8::oid4vci::AsMetadata =
        serde_json::from_value(parked.get("as_metadata").cloned().unwrap_or_default())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("the session AS: {e}")))?;
    let as_identifier = parked
        .get("as_identifier")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let pkce_verifier = parked
        .get("pkce_verifier")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let http = state.http_client();
    // (1) The token exchange (6.1: the code + PKCE + the redirect +
    // the private_key_jwt client assertion) bound with the DPoP
    // session (DESIGN 4b): one device key for the token + every
    // resource proof (the AS's cnf.jkt binding), the per-endpoint
    // nonce cache, and the use_dpop_nonce challenge-retry (RFC 9449
    // §5) - the AS's first 400 is the challenge, not a failure.
    let device_key = state.device_key(&user_id).await?;
    let mut dpop = wallet8::oid4vci::DpopSession::new(device_key.clone());
    // The session mints the RFC 7523 assertion PER ATTEMPT (a nonce
    // retry must re-sign with a fresh jti - RFC 7523 4.3 replay); the
    // client-attestation minter (when the attester identity is
    // present) rides each attempt as the two OAuth-Client-Attestation
    // headers (fresh PoP jti per attempt too).
    let attester_state = state.wallet_attestation_slot.read().await.clone();
    // The HAIP token-path challenge: a fresh challenge per exchange when
    // the AS advertises a challenge_endpoint (the suite validates the
    // PoP 'challenge' claim against the issued value at token time too).
    let token_challenge = match as_metadata.challenge_endpoint.as_deref() {
        Some(ce) => Some(
            wallet8::oid4vci::fetch_attestation_challenge(&http, ce)
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("haip challenge: {e}")))?,
        ),
        None => None,
    };
    let attestation_minter: Option<Box<dyn Fn() -> Result<wallet8::oid4vci::ClientAttestation, String> + Send + Sync>> =
        match attester_state {
            Some((attester, chain, issuer)) => {
                let as_id = as_identifier.clone();
                let client_id = state.wallet_client_id.clone();
                let dk = device_key.clone();
                let ch = token_challenge.clone();
                Some(Box::new(move || {
                    wallet8::oid4vci::mint_client_attestation(
                        // The PoP aud = the AS identifier itself (the
                        // exact issuer string, trailing slash included
                        // - the suite validates against the AS issuer,
                        // HAIP-4.4.1).
                        &attester, &chain, &issuer, &client_id, &dk, &as_id,
                        ch.as_deref(), 600,
                    )
                }))
            }
            None => None,
        };
    let token_response = dpop
        .exchange_code(
            &http,
            &as_metadata.token_endpoint,
            &state.wallet_client_id,
            &state.wallet_redirect_uri,
            &req.code,
            &pkce_verifier,
            Some(as_identifier.as_str()),
            attestation_minter.as_deref(),
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let access_token = token_response
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or((StatusCode::BAD_GATEWAY, "the token response carries no access_token (6.2)".into()))?
        .to_string();
    // (2) The target: the credential_identifiers when the token
    // response carried authorization_details (6.2), else the
    // configuration id (8.2).
    let target = match wallet8::oid4vci::credential_identifiers(&token_response) {
        Some(ids) => wallet8::oid4vci::CredentialRequestTarget::Identifier(
            ids.first().cloned().ok_or((StatusCode::BAD_GATEWAY, "no credential_identifiers (6.2)".into()))?,
        ),
        None => wallet8::oid4vci::CredentialRequestTarget::ConfigurationId(config_id.clone()),
    };
    // (3) The nonce pre-flight (7.1) + the proof (F.1) + the
    // credential request (8.2) - the DPoP session wraps the
    // protected call (the resource endpoint's own nonce challenge,
    // DESIGN 4b).
    let c_nonce = match &metadata.nonce_endpoint {
        Some(endpoint) => Some(
            wallet8::oid4vci::fetch_nonce(&http, endpoint)
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?,
        ),
        None => None,
    };
    let proof = wallet8::oid4vci::mint_jwt_proof(
        dpop.proof_key(),
        Some(state.wallet_client_id.as_str()),
        &credential_issuer,
        c_nonce.as_deref(),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // The batch behavior (OID4VCI 3.3.2): an advertised
    // batch_credential_issuance (batch_size >= 2) lets the wallet send
    // MULTIPLE independent proofs (each minted fresh over the device
    // key + c_nonce) - the response returns one credential PER proof,
    // possibly reordered. The holder sends a two-proof batch when the
    // advert allows it (the vault stores the credential bound to the
    // FIRST proof's key; both proofs sign over the same device key +
    // c_nonce so either holds).
    let advertised_batch = metadata
        .batch_credential_issuance
        .as_ref()
        .and_then(|b| b.get("batch_size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let proofs = if advertised_batch >= 2 {
        // VCIEnsureProofKeysAreDistinct: each proof in a batch binds
        // to a FRESH key (unlinkability - verifiers must not be able
        // to link the batch's credentials to one another). The
        // ephemeral key mints its proof with the same c_nonce +
        // audience; the main device-key proof stays first (the vault
        // stores the credential bound to the device key so the
        // presentation path keeps working).
        let ephemeral = p256::SecretKey::random(
            &mut p256::elliptic_curve::rand_core::OsRng,
        );
        let ephemeral_key = p256::ecdsa::SigningKey::from(&ephemeral);
        let proof2 = wallet8::oid4vci::mint_jwt_proof(
            &ephemeral_key,
            Some(state.wallet_client_id.as_str()),
            &credential_issuer,
            c_nonce.as_deref(),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        serde_json::json!({ "jwt": [proof, proof2] })
    } else {
        serde_json::json!({ "jwt": [proof] })
    };
    // The response-encryption material (8.2): mint an ephemeral key +
    // advertise it when the issuer advertises alg/enc - the issuer
    // answers with a JWE the wallet opens. The block rides the METADATA
    // TOP LEVEL (draft 16 moved it out of the configuration).
    let enc_pick: Option<(&'static str, &'static str)> =
        metadata
            .credential_response_encryption
            .as_ref()
            .and_then(|block| {
                let alg_ok = block
                    .get("alg_values_supported")
                    .and_then(|a| a.as_array())
                    .map(|a| a.iter().any(|v| v.as_str() == Some("ECDH-ES")))
                    .unwrap_or(false);
                if !alg_ok {
                    return None;
                }
                let enc = ["A256GCM", "A128GCM", "A256CBC-HS512", "A128CBC-HS256"]
                    .iter()
                    .find(|c| {
                        block
                            .get("enc_values_supported")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter().any(|v| v.as_str() == Some(**c)))
                            .unwrap_or(false)
                    })
                    .copied();
                enc.map(|e| ("ECDH-ES", e))
            });
    let response_encryption =
        enc_pick.map(|(alg, enc)| (wallet8::oid4vci::mint_response_encryption(), alg, enc));
    let mut request_body = wallet8::oid4vci::CredentialRequestBody {
        target,
        proofs,
        credential_response_encryption: None,
    };
    if let Some((material, alg, enc)) = &response_encryption {
        request_body.credential_response_encryption = Some(serde_json::json!({
            "jwk": material.jwk,
            "alg": alg,
            "enc": enc,
        }));
    }
    // The credential REQUEST encryption (8.2 encrypted variant): when
    // the issuer advertises credential_request_encryption with a key,
    // the body rides as a compact JWE (ECDH-ES + A256GCM) to that key.
    let body_value = serde_json::to_value(&request_body)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let req_jwk = metadata
        .credential_request_encryption
        .as_ref()
        .and_then(|r| r.get("jwks"))
        .and_then(|j| j.get("keys"))
        .and_then(|k| k.as_array())
        .and_then(|arr| arr.first())
        .cloned();
    let req_body_value = match (&req_jwk, &response_encryption) {
        // Seal only when the issuer's key is an EC P-256 key (the
        // ECDH-ES family the wallet implements).
        (Some(jwk), Some(_)) if jwk.get("kty").and_then(|v| v.as_str()) == Some("EC") => {
            let kid = jwk.get("kid").and_then(|v| v.as_str());
            let jwe = wallet8::oid4vci::encrypt_request_ecdh_es_a256gcm(
                &body_value,
                jwk,
                kid,
            )
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("the request seal: {e}")))?;
            serde_json::Value::String(jwe)
        }
        _ => body_value,
    };
    let response_text = dpop
        .post_protected_text(
            &http,
            &metadata.credential_endpoint,
            &access_token,
            &req_body_value,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let response_value = if response_text.trim_start().starts_with('{') {
        serde_json::from_str::<serde_json::Value>(&response_text)
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("credential response parse: {e}")))?
    } else if response_text.split('.').count() == 5 {
        let material = response_encryption
            .as_ref()
            .map(|(m, _, _)| m)
            .ok_or((StatusCode::BAD_GATEWAY, "the JWE response arrived without encryption material".to_string()))?;
        serde_json::to_value(
            wallet8::oid4vci::decrypt_ecdh_es_a256gcm(response_text.trim(), &material.sk)
                .map_err(|e| (StatusCode::BAD_GATEWAY, e))?,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    } else {
        return Err((StatusCode::BAD_GATEWAY, format!("the credential response is neither JSON nor a JWE ({} chars)", response_text.len())));
    };
    let response = wallet8::oid4vci::parse_credential_response(&response_value)
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    // (4) The store (8.3) + the notification (11).
    let configuration = metadata
        .credential_configurations_supported
        .get(&config_id)
        .cloned()
        .unwrap_or_default();
    let (minted, notification_id) = match response {
        wallet8::oid4vci::CredentialResponse::Issued { credentials, notification_id } => {
            let minted = credentials
                .first()
                .ok_or((StatusCode::BAD_GATEWAY, "no credentials minted (8.3)".into()))?
                .credential
                .clone();
            (minted, notification_id)
        }
        wallet8::oid4vci::CredentialResponse::Deferred { transaction_id, interval, notification_id } => {
            let deferred_session = format!("holder:vci:deferred:{transaction_id}");
            let deferred_parked = serde_json::json!({
                "credential_issuer": credential_issuer,
                "credential_endpoint": metadata.credential_endpoint,
                "deferred_credential_endpoint": metadata.deferred_credential_endpoint,
                "notification_endpoint": metadata.notification_endpoint,
                "notification_id": notification_id,
                "config_id": config_id,
                "format": configuration.get("format").and_then(|f| f.as_str()).unwrap_or("mso_mdoc"),
                "doctype": configuration.get("doctype").and_then(|d| d.as_str()),
                "vct": configuration.get("vct").and_then(|v| v.as_str()),
                "access_token": access_token,
            });
            let set_result: Result<String, glide::GlideError> = conn
                .set_ex(deferred_session.clone(), deferred_parked.to_string(), 86400u64)
                .await;
            if let Err(e) = set_result {
                tracing::error!(error = %e, key = %deferred_session,
                    "the deferred park write FAILED - the deferred poll will 404");
            }
            return Ok(Json(serde_json::json!({
                "status": "deferred",
                "transaction_id": transaction_id,
                "interval": interval,
            })));
        }
    };
    let format = configuration
        .get("format")
        .and_then(|f| f.as_str())
        .unwrap_or("mso_mdoc")
        .to_string();
    let doctype = configuration.get("doctype").and_then(|d| d.as_str()).map(str::to_string);
    let vct = configuration.get("vct").and_then(|v| v.as_str()).map(str::to_string);
    let sealed = sentin8::crypto::seal(&state.data_key, minted.as_bytes())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let row_id = Uuid::new_v4();
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(state.env_id)
        .execute(&mut *tx)
        .await;
    // The vault invariant: ONE holding per (env, user) per the unique
    // index - a renewed issuance REPLACES the holding (the wallet's
    // credential slot, DESIGN 3).
    sqlx::query!(
        r#"INSERT INTO holder.credentials
             (id, env_id, user_id, format, doctype, vct, display_name, issuer, credential_ct)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           ON CONFLICT (env_id, user_id) DO UPDATE
             SET format = EXCLUDED.format,
                 doctype = EXCLUDED.doctype,
                 vct = EXCLUDED.vct,
                 display_name = EXCLUDED.display_name,
                 issuer = EXCLUDED.issuer,
                 credential_ct = EXCLUDED.credential_ct,
                 issued_at = now()"#,
        row_id,
        state.env_id,
        user_id,
        format,
        doctype,
        vct,
        config_id,
        credential_issuer,
        sealed,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    if let (Some(endpoint), Some(notification_id)) =
        (metadata.notification_endpoint.as_deref(), notification_id.as_deref())
    {
        // The notification (§11) rides the same DPoP session - the
        // resource endpoint's own nonce challenge applies (DESIGN 4b).
        let notify_body = serde_json::json!({
            "notification_id": notification_id,
            "event": wallet8::oid4vci::NotificationEvent::CredentialAccepted.code(),
        });
        let _ = dpop
            .post_protected_notify(&http, endpoint, &access_token, &notify_body)
            .await;
    }
    Ok(Json(serde_json::json!({
        "id": row_id,
        "format": format,
        "display_name": config_id,
        "doctype": doctype,
        "vct": vct,
        "issuer": credential_issuer,
    })))
}


/// Standard-base64 no-pad form (the x5c encoding).
fn b64url(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
/// The client-attestation identity registration (the HAIP
/// client_attestation cells): the ATTESTER's PKCS#8 PEM + its x5c
/// chain + the attestation issuer id. The campaign-only surface -
/// the seed rotates the attester key per seed, so the identity flows
/// through the campaign env and the runner registers it before the
/// plans run (the same pattern the device-key registration uses).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AttestationIdentityRequest {
    /// The attester's PKCS#8 PEM private key (multi-line form).
    #[serde(default)]
    pub key_pem: Option<String>,
    /// The attester's PKCS#8 DER as single-line STANDARD base64 (the
    /// campaign env's newline-free form).
    #[serde(default)]
    pub key_der_b64: Option<String>,
    /// The attester's x5c chain (base64 DER entries).
    pub x5c: Vec<String>,
    /// The attestation issuer id the attestation claims.
    pub issuer: String,
}

/// `POST /v1/attestation-identity` - register the client-attestation
/// identity (the attester key/chain/issuer). Idempotent: the last
/// registration wins.
#[utoipa::path(
    post,
    path = "/v1/attestation-identity",
    request_body = AttestationIdentityRequest,
    responses((status = 200, description = "the identity registered")),
    tag = "holder",
)]
pub async fn register_attestation_identity(
    State(state): State<AppState>,
    Json(req): Json<AttestationIdentityRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use base64::Engine as _;
    use p256::pkcs8::DecodePrivateKey;
    let key = if let Some(pem) = req.key_pem.as_deref().filter(|p| !p.trim().is_empty()) {
        p256::SecretKey::from_pkcs8_pem(pem)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("the attester key (pem): {e}")))?
    } else if let Some(der_b64) = req.key_der_b64.as_deref().filter(|p| !p.trim().is_empty()) {
        let der = base64::engine::general_purpose::STANDARD
            .decode(der_b64.trim())
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("the attester key (der): {e}")))?;
        p256::SecretKey::from_pkcs8_der(&der)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("the attester key (der parse): {e}")))?
    } else {
        return Err((StatusCode::BAD_REQUEST, "no attester key material (key_pem or key_der_b64)".into()));
    };
    let signing = p256::ecdsa::SigningKey::from(key);
    // Self-check: the x5c LEAF must certify the PUBLIC half of the
    // PEM key (a mismatched pair would produce attestations the suite
    // rejects far from the cause).
    if let Some(leaf_b64) = req.x5c.last() {
        use base64::Engine as _;
        let der = base64::engine::general_purpose::STANDARD
            .decode(leaf_b64.trim())
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("the leaf x5c: {e}")))?;
        let (_, leaf) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("the leaf parse: {e}")))?;
        let want = wallet8::oid4vci::device_key_jwk(&signing.verifying_key());
        let spki = leaf.public_key().subject_public_key.data.to_vec();
        // EC SPKI: 0x04 | X | Y (65 bytes for P-256) - the raw point.
        if spki.len() == 65 {
            let got = serde_json::json!({
                "kty": "EC", "crv": "P-256",
                "x": b64url(&spki[1..33]),
                "y": b64url(&spki[33..65]),
            });
            if got != want {
                return Err((StatusCode::BAD_REQUEST, "the attester PEM and its x5c leaf are a DIFFERENT keypair".into()));
            }
        }
    }
    {
        let mut slot = state.wallet_attestation_slot.write().await;
        *slot = Some((signing, req.x5c.clone(), req.issuer.clone()));
    }
    
    Ok(Json(serde_json::json!({"status": "registered"})))
}

/// The deferred-poll request (§9).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DeferredRequest {
    /// The deferred transaction id.
    pub transaction_id: String,
}

/// Decode a Deferred Credential Response (§9.2) - the holder-side
/// form of the SDK's DeferredAnswer (the DpopSession-protected poll
/// returns the raw value).
fn parse_deferred_answer(
    v: &serde_json::Value,
) -> Result<wallet8::oid4vci::DeferredAnswer, String> {
    if let Some(creds) = v.get("credentials").and_then(|c| c.as_array()) {
        let mut out = Vec::new();
        for entry in creds {
            out.push(wallet8::oid4vci::MintedCredential {
                credential: entry
                    .get("credential")
                    .and_then(|c| c.as_str())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        return Ok(wallet8::oid4vci::DeferredAnswer::Issued(out));
    }
    if let Some(tx) = v.get("transaction_id").and_then(|t| t.as_str()) {
        let interval = v.get("interval").and_then(|i| i.as_u64()).unwrap_or(0);
        return Ok(wallet8::oid4vci::DeferredAnswer::Pending {
            transaction_id: tx.to_string(),
            interval,
        });
    }
    Err("the deferred response carries neither credentials nor transaction_id (§9.2)".into())
}

/// `POST /v1/issuance/deferred` - the §9 poll: the parked
/// transaction re-submits (the same access token); the 200 form
/// stores, the 202 form answers pending. `credential_request_denied`
/// is terminal (§9.3).
#[utoipa::path(
    post,
    path = "/v1/issuance/deferred",
    request_body = DeferredRequest,
    responses((status = 200, description = "The stored credential or the pending marker")),
    tag = "holder",
)]
pub async fn issuance_deferred(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
    Json(req): Json<DeferredRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_id = crate::server::caller_user_id(&query).await?;
    use glide::AsyncCommands as _;
    let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let parked_raw: Option<String> = conn
        .get(format!("holder:vci:deferred:{}", req.transaction_id))
        .await
        .ok()
        .flatten();
    let parked_raw = parked_raw
        .ok_or((StatusCode::NOT_FOUND, "the deferred transaction expired or is unknown".into()))?;
    let parked: serde_json::Value = serde_json::from_str(&parked_raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("the parked parse: {e}")))?;
    let http = state.http_client();
    // The AS's deferred endpoint (9.1) - the PARKED row carries the
    // already-resolved deferred_credential_endpoint (re-resolving the
    // issuer metadata here would form the WRONG .well-known path for
    // the suite's path-bearing issuer identifier - RFC8414 §1 puts the
    // path COMPONENT AFTER the well-known prefix).
    let deferred_endpoint = parked
        .get("deferred_credential_endpoint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or((StatusCode::NOT_IMPLEMENTED, "the parked row carries no deferred endpoint".into()))?
        .to_string();
    let issuer = parked.get("credential_issuer").and_then(|v| v.as_str()).unwrap_or_default();
    let access_token = parked
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    // The poll (9.1: the transaction_id + the same access token) - the
    // DPoP session wraps the deferred call (a resource endpoint; its own
    // nonce challenge applies, DESIGN 4b).
    let device_key = state.device_key(&user_id).await?;
    let mut dpop = wallet8::oid4vci::DpopSession::new(device_key);
    let poll_body = serde_json::json!({ "transaction_id": req.transaction_id });
    let answer_value = dpop
        .post_protected_json(&http, &deferred_endpoint, &access_token, &poll_body)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let answer = parse_deferred_answer(&answer_value)
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    match answer {
        wallet8::oid4vci::DeferredAnswer::Pending { transaction_id, interval } => Ok(Json(
            serde_json::json!({"status": "pending", "transaction_id": transaction_id, "interval": interval}),
        )),
        wallet8::oid4vci::DeferredAnswer::Issued(creds) => {
            // The §9.2 200 carries the OPTIONAL notification_id (the
            // deferred-notification variant: the notification rides the
            // ISSUE, not the original credential response).
            let notification_id = answer_value
                .get("notification_id")
                .and_then(|n| n.as_str())
                .map(str::to_string);
            let minted = creds
                .first()
                .ok_or((StatusCode::BAD_GATEWAY, "no credentials minted (9.2)".into()))?
                .credential
                .clone();
            let format = parked.get("format").and_then(|v| v.as_str()).unwrap_or("mso_mdoc").to_string();
            let doctype = parked.get("doctype").and_then(|v| v.as_str()).map(str::to_string);
            let vct = parked.get("vct").and_then(|v| v.as_str()).map(str::to_string);
            let config_id = parked.get("config_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let sealed = sentin8::crypto::seal(&state.data_key, minted.as_bytes())
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let row_id = Uuid::new_v4();
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
                r#"INSERT INTO holder.credentials
                     (id, env_id, user_id, format, doctype, vct, display_name, issuer, credential_ct)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                   ON CONFLICT (env_id, user_id) DO UPDATE
                     SET format = EXCLUDED.format,
                         doctype = EXCLUDED.doctype,
                         vct = EXCLUDED.vct,
                         display_name = EXCLUDED.display_name,
                         issuer = EXCLUDED.issuer,
                         credential_ct = EXCLUDED.credential_ct,
                         issued_at = now()"#,
                row_id,
                state.env_id,
                user_id,
                format,
                doctype,
                vct,
                config_id,
                issuer,
                sealed,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = tx.commit().await;
            // The terminal notification (11) when the deferred flow
            // carried one - through the same DPoP session (DESIGN 4b:
            // the resource endpoint's own nonce challenge applies).
            // The id rides the PARKED row when the original credential
            // response carried it, else the POLL's 200 (the deferred-
            // notification variant).
            let notification_id = notification_id.or_else(|| {
                parked.get("notification_id").and_then(|n| n.as_str()).map(str::to_string)
            });
            if let (Some(endpoint), Some(nid)) = (
                parked.get("notification_endpoint").and_then(|v| v.as_str()),
                notification_id.as_deref(),
            ) {
                let notify_body = serde_json::json!({
                    "notification_id": nid,
                    "event": wallet8::oid4vci::NotificationEvent::CredentialAccepted.code(),
                });
                let _ = dpop
                    .post_protected_notify(&http, endpoint, &access_token, &notify_body)
                    .await;
            }
            // The transaction is consumed (9.1: the issuer
            // invalidates it).
            let _: Result<(), _> = conn.del(format!("holder:vci:deferred:{}", req.transaction_id)).await;
            Ok(Json(serde_json::json!({
                "status": "issued",
                "id": row_id,
                "format": format,
                "display_name": config_id,
                "doctype": doctype,
                "vct": vct,
                "issuer": issuer,
            })))
        }
    }
}

/// `POST /v1/credentials/sync` - the vault's status walk (§11.6):
/// every active SD-JWT VC row's `status.status_list` reference is
/// fetched (TTL-cached) + checked; a non-VALID entry flips the row
/// to `revoked` (the business event). A fetch failure treats the
/// credential as unverifiable - fail-closed (TSL §8.3: no statement
/// = reject).
#[utoipa::path(
    post,
    path = "/v1/credentials/sync",
    responses((status = 200, description = "The sync summary")),
    tag = "holder",
)]
pub async fn credentials_sync(
    State(state): State<AppState>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
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
    let rows = sqlx::query!(
        r#"SELECT id, format, credential_ct FROM holder.credentials
           WHERE user_id = $1 AND status = 'active' AND format = 'dc+sd-jwt'"#,
        user_id,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    let http = state.http_client();
    let mut revoked = 0usize;
    let mut checked = 0usize;
    for row in rows {
        let material = sentin8::crypto::open_str(&state.data_key, &row.credential_ct)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let text = String::from_utf8_lossy(&material).to_string();
        // The payload segment (the sd-jwt's claims - the vault's
        // sd_jwt_claims view).
        let payload = crate::server::sd_jwt_payload(&text)
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "the stored sd-jwt carries no payload".into()))?;
        let reference = wallet8::oid4vp::decode_status_reference(&payload)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
        let Some(reference) = reference else { continue };
        checked += 1;
        // The cache-first fetch (TSL 13.7: the Valkey-cached list per
        // uri; the failure = fail-closed).
        let cache_key = format!("status:list:{}", reference.uri);
        let list_jwt: Option<String> = {
            use glide::AsyncCommands as _;
            let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            conn.get(&cache_key).await.ok().flatten()
        };
        let list = match list_jwt {
            Some(cached) => wallet8::oid4vp::parse_status_list_token(&cached)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?,
            None => {
                let fetched = wallet8::oid4vp::fetch_status_list(&http, &reference.uri)
                    .await
                    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
                // Re-cache (the ttl claim's window; 5 min default).
                let ttl = fetched.ttl.unwrap_or(300).min(3600);
                {
                    use glide::AsyncCommands as _;
                    let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
                        .await
                        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                    // The raw JWT re-fetch: the parsed list re-mints
                    // unsigned - cache the parsed entries instead.
                    let parked = serde_json::json!({
                        "bits": fetched.bits,
                        "entries": base64::Engine::encode(
                            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                            &fetched.entries,
                        ),
                        "uri": fetched.uri,
                    });
                    let _: Result<(), _> = conn
                        .set_ex(&cache_key, parked.to_string(), ttl)
                        .await;
                }
                fetched
            }
        };
        let value = wallet8::oid4vp::entry_value(&list.entries, list.bits, reference.idx);
        if !value.presents() {
            // The flip (the business event:
            // wallet8:holder:credential:revoked).
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
                r#"UPDATE holder.credentials SET status = 'revoked'
                   WHERE id = $1"#,
                row.id,
            )
            .execute(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            let _ = tx.commit().await;
            revoked += 1;
        }
    }
    Ok(Json(serde_json::json!({
        "checked": checked,
        "revoked": revoked,
    })))
}
