use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    middleware::auth::AuthenticatedUser,
    models::user::User,
    services::AppState,
    utils::errors::AppError,
    utils::totp::{
        generate_backup_codes as generate_totp_backup_codes, generate_totp_secret,
        generate_totp_uri, verify_totp_code,
    },
};

#[derive(Debug, Serialize, ToSchema)]
pub struct SetupTotpResponse {
    pub secret: String,
    pub qr_uri: String,
    pub message: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConfirmTotpRequest {
    /// The 6-digit code from the authenticator app to confirm setup worked
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyTotpRequest {
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableTotpRequest {
    /// Current password required to disable MFA (security check)
    pub password: String,
    pub code: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BackupCodesResponse {
    pub backup_codes: Vec<String>,
    pub message: String,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/mfa")
            .route("/totp/setup", web::post().to(setup_totp))
            .route("/totp/confirm", web::post().to(confirm_totp))
            .route("/totp/disable", web::post().to(disable_totp))
            .route("/totp/verify", web::post().to(verify_totp))
            .route("/backup-codes", web::post().to(generate_backup_codes))
            .route("/backup-codes", web::get().to(view_backup_codes)),
    );
}

/// Step 1 of MFA setup: generate a TOTP secret and QR code URI
/// The user scans the QR code with their authenticator app
#[utoipa::path(
    post,
    path = "/api/v1/mfa/totp/setup",
    tag = "mfa",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "TOTP setup initiated", body = SetupTotpResponse),
        (status = 400, description = "MFA already enabled"),
    )
)]
pub async fn setup_totp(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    let user = get_user(&state, auth_user.user_id).await?;

    if user.totp_enabled {
        return Err(AppError::BadRequest(
            "MFA is already enabled. Disable it first before setting up again.".into(),
        ));
    }

    // Generate a new secret and store it temporarily (not confirmed yet)
    let secret = generate_totp_secret();
    let qr_uri = generate_totp_uri(&secret, &user.email, "RustAuth");

    // Store the secret (unconfirmed - only enabled after user confirms it works)
    sqlx::query("UPDATE users SET totp_secret = $1, updated_at = NOW() WHERE id = $2")
        .bind(&secret)
        .bind(user.id)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(SetupTotpResponse {
        secret: secret.clone(),
        qr_uri,
        message: "Scan the QR code with your authenticator app, then confirm with a 6-digit code"
            .into(),
    }))
}

/// Step 2 of MFA setup: confirm the TOTP code works
/// After confirming, MFA is officially enabled on the account
#[utoipa::path(
    post,
    path = "/api/v1/mfa/totp/confirm",
    tag = "mfa",
    security(("bearer_auth" = [])),
    request_body = ConfirmTotpRequest,
    responses(
        (status = 200, description = "MFA enabled successfully", body = BackupCodesResponse),
        (status = 400, description = "Invalid code or MFA not set up"),
    )
)]
pub async fn confirm_totp(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<ConfirmTotpRequest>,
) -> Result<HttpResponse, AppError> {
    let user = get_user(&state, auth_user.user_id).await?;

    if user.totp_enabled {
        return Err(AppError::BadRequest("MFA is already enabled".into()));
    }

    let secret = user
        .totp_secret
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Run /mfa/totp/setup first".into()))?;

    let valid = verify_totp_code(secret, &body.code)?;
    if !valid {
        return Err(AppError::BadRequest(
            "Invalid MFA code. Make sure your device time is correct.".into(),
        ));
    }

    // Generate backup codes for account recovery
    let backup_codes = generate_totp_backup_codes(10);
    let codes_json = serde_json::to_value(&backup_codes)
        .map_err(|_| AppError::Internal("Failed to serialize backup codes".into()))?;

    sqlx::query(
        "UPDATE users SET totp_enabled = true, totp_backup_codes = $1, updated_at = NOW() WHERE id = $2"
    )
    .bind(codes_json)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    tracing::info!("MFA enabled for user: {}", user.email);

    Ok(HttpResponse::Ok().json(BackupCodesResponse {
        backup_codes,
        message:
            "MFA enabled! Save these backup codes somewhere safe. Each code can only be used once."
                .into(),
    }))
}

/// Disable TOTP MFA (requires password + current TOTP code for security)
#[utoipa::path(
    post,
    path = "/api/v1/mfa/totp/disable",
    tag = "mfa",
    security(("bearer_auth" = [])),
    request_body = DisableTotpRequest,
    responses(
        (status = 200, description = "MFA disabled"),
        (status = 400, description = "Invalid password or code"),
    )
)]
pub async fn disable_totp(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<DisableTotpRequest>,
) -> Result<HttpResponse, AppError> {
    let user = get_user(&state, auth_user.user_id).await?;

    if !user.totp_enabled {
        return Err(AppError::BadRequest("MFA is not enabled".into()));
    }

    // Verify password first
    let hash = user.password_hash.as_deref().unwrap_or("");
    if !crate::utils::password::verify_password(&body.password, hash)? {
        return Err(AppError::BadRequest("Incorrect password".into()));
    }

    // Verify the TOTP code
    let secret = user.totp_secret.as_deref().unwrap_or("");
    let valid = verify_totp_code(secret, &body.code)?;
    if !valid {
        return Err(AppError::BadRequest("Invalid MFA code".into()));
    }

    sqlx::query(
        "UPDATE users SET totp_enabled = false, totp_secret = NULL, totp_backup_codes = NULL, updated_at = NOW() WHERE id = $1"
    )
    .bind(user.id)
    .execute(&state.db)
    .await?;

    tracing::info!("MFA disabled for user: {}", user.email);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "MFA has been disabled"
    })))
}

/// Verify a TOTP code (used during login when MFA_REQUIRED is returned)
#[utoipa::path(
    post,
    path = "/api/v1/mfa/totp/verify",
    tag = "mfa",
    security(("bearer_auth" = [])),
    request_body = VerifyTotpRequest,
    responses(
        (status = 200, description = "Code is valid"),
        (status = 400, description = "Invalid code"),
    )
)]
pub async fn verify_totp(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<VerifyTotpRequest>,
) -> Result<HttpResponse, AppError> {
    let user = get_user(&state, auth_user.user_id).await?;

    if !user.totp_enabled {
        return Err(AppError::BadRequest("MFA is not enabled".into()));
    }

    let secret = user.totp_secret.as_deref().unwrap_or("");
    let valid = verify_totp_code(secret, &body.code)?;

    if !valid {
        return Err(AppError::BadRequest("Invalid MFA code".into()));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Code verified"
    })))
}

/// Generate new backup codes (invalidates old ones)
#[utoipa::path(
    post,
    path = "/api/v1/mfa/backup-codes",
    tag = "mfa",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "New backup codes generated", body = BackupCodesResponse),
        (status = 400, description = "MFA not enabled"),
    )
)]
pub async fn generate_backup_codes(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    let user = get_user(&state, auth_user.user_id).await?;

    if !user.totp_enabled {
        return Err(AppError::BadRequest(
            "MFA must be enabled to generate backup codes".into(),
        ));
    }

    let codes = generate_totp_backup_codes(10);
    let codes_json = serde_json::to_value(&codes)
        .map_err(|_| AppError::Internal("Failed to serialize backup codes".into()))?;

    sqlx::query("UPDATE users SET totp_backup_codes = $1, updated_at = NOW() WHERE id = $2")
        .bind(codes_json)
        .bind(user.id)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(BackupCodesResponse {
        backup_codes: codes,
        message: "New backup codes generated. Old codes are now invalid. Store these safely!"
            .into(),
    }))
}

/// View how many backup codes remain (not the codes themselves)
#[utoipa::path(
    get,
    path = "/api/v1/mfa/backup-codes",
    tag = "mfa",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Backup code count"),
    )
)]
pub async fn view_backup_codes(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    let user = get_user(&state, auth_user.user_id).await?;

    let count = user
        .totp_backup_codes
        .as_ref()
        .and_then(|codes| serde_json::from_value::<Vec<String>>(codes.clone()).ok())
        .map(|codes| codes.len())
        .unwrap_or(0);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "remaining_backup_codes": count,
            "mfa_enabled": user.totp_enabled,
        }
    })))
}

async fn get_user(state: &web::Data<AppState>, user_id: uuid::Uuid) -> Result<User, AppError> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))
}
