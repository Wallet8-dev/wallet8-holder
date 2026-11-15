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
            "the authorization-code intake lands with the browser round \
             (the PAR orchestration endpoint pair)"
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
    // The tx_code VALUE comes from the End-User; the first intake
    // pass supplies an empty string for the present-but-unfilled
    // object (4.1.1 demands the parameter; the interactive prompt
    // lands with the app's consent UI).
    let tx_code_value: Option<String> = grant.1.as_ref().map(|_| String::new());
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
    let response = wallet8::oid4vci::request_credential(
        &http,
        &metadata.credential_endpoint,
        &access_token,
        &wallet8::oid4vci::CredentialRequestBody {
            target,
            proofs: serde_json::json!({ "jwt": [proof] }),
            credential_response_encryption: None,
        },
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    // (5) The vault store (8.3: the immediate form stores; the
    //     deferred form records the transaction for the 9 poll; the
    //     11 notification rides the notification_id).
    let minted = match response {
        wallet8::oid4vci::CredentialResponse::Issued(creds) => creds
            .first()
            .ok_or((StatusCode::BAD_GATEWAY, "no credentials minted (8.3)".into()))?
            .clone(),
        wallet8::oid4vci::CredentialResponse::Deferred { .. } => {
            return Err((
                StatusCode::ACCEPTED,
                "the issuer deferred the credential (9) - the poll \
                 orchestration lands with the app's pending state"
                    .into(),
            ))
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
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
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
}

/// `POST /v1/presentation/resolve` - the pre-consent preview: parse
/// the verifier's request object, match the DCQL query against the
/// vault, and return the requested claims + the verifier identity
/// (the consent screen; a malformed/unsafe request answers the
/// error - the app renders the error screen).
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
    // The JAR payload (the signed object's claims - the signature
    // verify rides the trust-anchor surface; the shape gate runs
    // first: a malformed request never reaches the consent screen).
    let payload = crate::server::jar_claims(&object)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let request = wallet8::oid4vp::parse_request(&payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    wallet8::oid4vp::check_request_shape(&request)
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
    let session_key = format!("vp:req:{}", uuid::Uuid::new_v4());
    {
        use glide::AsyncCommands as _;
        let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let _: Result<(), _> = conn
            .set_ex(&session_key, payload.clone(), 600u64)
            .await;
    }
    Ok(Json(serde_json::json!({
        "session": session_key,
        "verifier": request.client_id,
        "nonce": request.nonce,
        "credentials": preview,
    })))
}

/// The presentation-deliver request (the post-consent flow).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PresentRequest {
    /// The resolve step's session key.
    pub session: String,
    /// The user's consent decision.
    pub approved: bool,
}

/// `POST /v1/presentation/present` - the post-consent delivery: the
/// vp_token assembly (the mdoc DeviceResponse / the sd-jwt + KB) and
/// the direct_post/dc_api submission; the history record rides the
/// same transaction. A denied/unsatisfiable request answers the
/// prescribed error - never an empty vp_token.
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
    // The consent gate (15.1: explicit consent before any release).
    if !req.approved {
        return Ok(Json(wallet8::oid4vp::error_response(
            wallet8::oid4vp::WalletError::AccessDenied,
            "the user declined to share the requested credentials (8.5)",
            None,
        )));
    }
    // The resolve step's session (the resolved request object).
    use glide::AsyncCommands as _;
    let conn = sentin8::middleware::valkey_client(&state.valkey_url, "wallet8:holder")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let payload: Option<String> = conn
        .get(format!("vp:req:{}", req.session.trim_start_matches("vp:req:")))
        .await
        .ok()
        .flatten();
    let payload = payload
        .ok_or((StatusCode::NOT_FOUND, "the presentation session expired".into()))?;
    let request = wallet8::oid4vp::parse_request(&payload)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    wallet8::oid4vp::check_request_shape(&request)
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
    let vp_token = wallet8::oid4vp::build_vp_token(&matches, &device_key, &request, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    // The delivery (8.2 direct_post; the 200 JSON may carry the
    // redirect_uri the app must open in the browser).
    let http = state.http_client();
    let response_uri = request
        .response_uri
        .clone()
        .ok_or((StatusCode::BAD_REQUEST, "the request carries no response_uri (8.2)".into()))?;
    let outcome = wallet8::oid4vp::post_response(&http, &response_uri, &vp_token, request.state.as_deref())
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
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
        response_uri,
        &disclosed,
        &formats,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = tx.commit().await;
    Ok(Json(serde_json::json!({
        "status": "presented",
        "redirect_uri": outcome.redirect_uri,
        "presented": matches.iter().map(|m| m.query.id.clone()).collect::<Vec<_>>(),
    })))
}
