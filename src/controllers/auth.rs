use actix_web::{HttpRequest, HttpResponse, web};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    middleware::auth::AuthenticatedUser,
    models::{session::Session, user::PublicUser},
    services::{AppState, EmailService},
    utils::{
        errors::AppError,
        jwt::{create_access_token, create_refresh_token, verify_refresh_token},
        password::{hash_password, validate_password_strength, verify_password},
        totp::generate_secure_token,
    },
};

// ---- Private helpers ----

fn get_client_ip(req: &HttpRequest) -> Option<String> {
    // Check common proxy headers first
    req.headers()
        .get("X-Forwarded-For")
        .or_else(|| req.headers().get("X-Real-IP"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| req.peer_addr().map(|a| a.ip().to_string()))
}

/// Create a new session and return (access_token, refresh_token, session_id)
async fn create_session(
    state: &web::Data<AppState>,
    user: &crate::models::user::User,
    req: &HttpRequest,
    is_oauth: bool,
    oauth_provider: Option<&str>,
) -> Result<(String, String, Uuid), AppError> {
    let session_id = Uuid::new_v4();
    let ip = get_client_ip(req);
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let refresh_token = create_refresh_token(
        user.id,
        session_id,
        &state.config.jwt.refresh_secret,
        state.config.jwt.refresh_expiry_days,
    )?;

    let access_token = create_access_token(
        user.id,
        user.role.clone(),
        user.is_email_verified,
        &state.config.jwt.access_secret,
        state.config.jwt.access_expiry_minutes,
    )?;

    let expires_at = Utc::now() + Duration::days(state.config.jwt.refresh_expiry_days);
    let token_hash = format!("{:x}", refresh_token.len()); // Simplified hash

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, token_hash, user_agent, ip_address, is_oauth, oauth_provider, expires_at, created_at, last_used_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
        "#
    )
    .bind(session_id)
    .bind(user.id)
    .bind(&token_hash)
    .bind(&user_agent)
    .bind(&ip)
    .bind(is_oauth)
    .bind(oauth_provider)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok((access_token, refresh_token, session_id))
}

pub async fn verify_backup_code(
    state: &web::Data<AppState>,
    user: &crate::models::user::User,
    code: &str,
) -> Result<bool, AppError> {
    let backup_codes = match &user.totp_backup_codes {
        Some(codes) => codes.clone(),
        None => return Ok(false),
    };

    let codes: Vec<String> = serde_json::from_value(backup_codes)
        .map_err(|_| AppError::Internal("Invalid backup codes format".into()))?;

    let normalized = code.trim().to_uppercase();
    let pos = codes.iter().position(|c| c.to_uppercase() == normalized);

    if let Some(idx) = pos {
        // Remove the used backup code (they're single-use)
        let mut updated_codes = codes;
        updated_codes.remove(idx);
        let new_codes = serde_json::to_value(&updated_codes)
            .map_err(|_| AppError::Internal("Failed to serialize backup codes".into()))?;

        sqlx::query("UPDATE users SET totp_backup_codes = $1, updated_at = NOW() WHERE id = $2")
            .bind(new_codes)
            .bind(user.id)
            .execute(&state.db)
            .await?;

        return Ok(true);
    }

    Ok(false)
}

// ---- Request/Response types ----

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(email(message = "Must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,
    #[validate(length(min = 2, max = 50))]
    pub display_name: Option<String>,
    #[validate(length(min = 3, max = 30, message = "Username must be 3-30 characters"))]
    pub username: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    pub password: String,
    /// TOTP code if MFA is enabled
    pub totp_code: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ForgotPasswordRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    pub token: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub success: bool,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: PublicUser,
}

// ---- Route configuration ----
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/logout", web::post().to(logout))
            .route("/refresh", web::post().to(refresh_token))
            .route("/forgot-password", web::post().to(forgot_password))
            .route("/reset-password", web::post().to(reset_password))
            .route("/verify-email", web::get().to(verify_email))
            .route("/resend-verification", web::post().to(resend_verification)),
    );
}

// ---- Handlers ----

/// Register a new user account
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = AuthResponse),
        (status = 400, description = "Validation error"),
        (status = 409, description = "Email or username already exists"),
    )
)]
pub async fn register(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    // Check password strength
    validate_password_strength(&body.password).map_err(|e| AppError::BadRequest(e))?;

    // Check if email is already taken
    let existing = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE email = $1")
        .bind(&body.email.to_lowercase())
        .fetch_one(&state.db)
        .await?;

    if existing > 0 {
        return Err(AppError::BadRequest(
            "Email address is already in use".into(),
        ));
    }

    // Check username uniqueness if provided
    if let Some(ref username) = body.username {
        let username_taken =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE username = $1")
                .bind(username)
                .fetch_one(&state.db)
                .await?;

        if username_taken > 0 {
            return Err(AppError::BadRequest("Username is already taken".into()));
        }
    }

    let password_hash = hash_password(&body.password)?;
    let verification_token = generate_secure_token(64);
    let token_expiry =
        Utc::now() + Duration::minutes(state.config.security.email_token_expiry_minutes);
    let ip = get_client_ip(&req);

    // Insert the new user
    let user = sqlx::query_as::<_, crate::models::user::User>(
        r#"
                        INSERT INTO users (
                            id, email, username, display_name, password_hash,
                            email_verification_token, email_verification_expires_at,
                            last_login_ip, created_at, updated_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
                        RETURNING *
                        "#,
    )
    .bind(Uuid::new_v4())
    .bind(body.email.to_lowercase())
    .bind(&body.username)
    .bind(&body.display_name)
    .bind(&password_hash)
    .bind(&verification_token)
    .bind(token_expiry)
    .bind(&ip)
    .fetch_one(&state.db)
    .await?;

    // Send verification email (don't fail registration if this fails)
    let email_service = EmailService::new(state.config.email.clone());
    let display_name = user.display_name.as_deref().unwrap_or(&user.email);
    if let Err(e) = email_service
        .send_verification_email(&user.email, display_name, &verification_token)
        .await
    {
        tracing::warn!("Failed to send verification email: {:?}", e);
    }

    // Create a session and tokens
    let (access_token, refresh_token, _) = create_session(&state, &user, &req, false, None).await?;

    tracing::info!("New user registered: {}", user.email);

    Ok(HttpResponse::Created().json(AuthResponse {
        success: true,
        access_token,
        refresh_token,
        expires_in: state.config.jwt.access_expiry_minutes * 60,
        user: user.into(),
    }))
}

/// Login with email and password
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 400, description = "Invalid credentials"),
        (status = 403, description = "Account locked or email not verified"),
        (status = 401, description = "MFA code required"),
    )
)]
pub async fn login(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    // Find the user
    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE email = $1 AND is_active = true",
    )
    .bind(&body.email.to_lowercase())
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Invalid email or password".into()))?;

    // Check if account is locked
    if user.is_locked() {
        let locked_until = user.locked_until.unwrap();
        return Err(AppError::AccountLocked(format!(
            "Account locked until {}. Too many failed login attempts.",
            locked_until.format("%Y-%m-%d %H:%M UTC")
        )));
    }

    // Verify password
    let password_hash = user.password_hash.as_deref().unwrap_or("");
    let password_ok = verify_password(&body.password, password_hash)?;

    if !password_ok {
        // Increment failed attempts
        let new_attempts = user.failed_login_attempts + 1;
        let max_attempts = state.config.security.max_login_attempts as i32;

        if new_attempts >= max_attempts {
            // Lock the account
            let lock_until =
                Utc::now() + Duration::minutes(state.config.security.lockout_duration_minutes);
            sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, locked_until = $2, updated_at = NOW() WHERE id = $3"
            )
            .bind(new_attempts)
            .bind(lock_until)
            .bind(user.id)
            .execute(&state.db)
            .await?;

            tracing::warn!(
                "Account locked due to too many failed attempts: {}",
                user.email
            );
            return Err(AppError::AccountLocked(format!(
                "Account locked for {} minutes due to too many failed attempts",
                state.config.security.lockout_duration_minutes
            )));
        } else {
            sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(new_attempts)
            .bind(user.id)
            .execute(&state.db)
            .await?;
        }

        return Err(AppError::Unauthorized("Invalid email or password".into()));
    }

    // Check email verification
    if state.config.security.require_email_verification && !user.is_email_verified {
        return Err(AppError::EmailNotVerified);
    }

    // Check TOTP if enabled
    if user.totp_enabled {
        match &body.totp_code {
            None => return Err(AppError::MfaRequired),
            Some(code) => {
                let secret = user.totp_secret.as_deref().unwrap_or("");
                let valid = crate::utils::totp::verify_totp_code(secret, code)?;

                if !valid {
                    // Check backup codes
                    let backup_valid = verify_backup_code(&state, &user, code).await?;
                    if !backup_valid {
                        return Err(AppError::Unauthorized("Invalid MFA code".into()));
                    }
                }
            }
        }
    }

    // Reset failed attempts on successful login
    let ip = get_client_ip(&req);
    sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), last_login_ip = $1, updated_at = NOW() WHERE id = $2"
    )
    .bind(&ip)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    let (access_token, refresh_token, _) = create_session(&state, &user, &req, false, None).await?;

    // Re-fetch user to get updated login time
    let updated_user =
        sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&state.db)
            .await?;

    tracing::info!("User logged in: {}", user.email);

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        access_token,
        refresh_token,
        expires_in: state.config.jwt.access_expiry_minutes * 60,
        user: updated_user.into(),
    }))
}

/// Logout - invalidate the current session
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Logged out successfully"),
    )
)]
pub async fn logout(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<RefreshTokenRequest>,
) -> Result<HttpResponse, AppError> {
    // Revoke the session associated with this refresh token
    let claims = verify_refresh_token(&body.refresh_token, &state.config.jwt.refresh_secret)?;
    let session_id = Uuid::parse_str(&claims.session_id)
        .map_err(|_| AppError::BadRequest("Invalid session ID".into()))?;

    sqlx::query("UPDATE sessions SET is_revoked = true WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(auth_user.user_id)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

/// Refresh access token using a refresh token
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    request_body = RefreshTokenRequest,
    responses(
        (status = 200, description = "Token refreshed", body = AuthResponse),
        (status = 401, description = "Invalid or expired refresh token"),
    )
)]
pub async fn refresh_token(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<RefreshTokenRequest>,
) -> Result<HttpResponse, AppError> {
    let claims = verify_refresh_token(&body.refresh_token, &state.config.jwt.refresh_secret)?;

    let session_id = Uuid::parse_str(&claims.session_id)
        .map_err(|_| AppError::Unauthorized("Invalid session".into()))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Unauthorized("Invalid user ID".into()))?;

    // Verify the session is still valid
    let session = sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE id = $1 AND user_id = $2 AND is_revoked = false AND expires_at > NOW()"
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Session expired or revoked".into()))?;

    // Get the user
    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("User not found or inactive".into()))?;

    // Issue new tokens (token rotation - old refresh token is revoked)
    sqlx::query("UPDATE sessions SET is_revoked = true WHERE id = $1")
        .bind(session.id)
        .execute(&state.db)
        .await?;

    let (access_token, refresh_token, _) = create_session(
        &state,
        &user,
        &req,
        session.is_oauth,
        session.oauth_provider.as_deref(),
    )
    .await?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        success: true,
        access_token,
        refresh_token,
        expires_in: state.config.jwt.access_expiry_minutes * 60,
        user: user.into(),
    }))
}

/// Request a password reset email
#[utoipa::path(
    post,
    path = "/api/v1/auth/forgot-password",
    tag = "auth",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Reset email sent if account exists"),
    )
)]
pub async fn forgot_password(
    state: web::Data<AppState>,
    body: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    // We ALWAYS return success even if the email doesn't exist.
    // This prevents attackers from finding out which emails are registered.
    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE email = $1 AND is_active = true",
    )
    .bind(&body.email.to_lowercase())
    .fetch_optional(&state.db)
    .await?;

    if let Some(user) = user {
        let token = generate_secure_token(64);
        let expiry =
            Utc::now() + Duration::minutes(state.config.security.password_reset_expiry_minutes);

        sqlx::query(
            "UPDATE users SET password_reset_token = $1, password_reset_expires_at = $2, updated_at = NOW() WHERE id = $3"
        )
        .bind(&token)
        .bind(expiry)
        .bind(user.id)
        .execute(&state.db)
        .await?;

        let email_service = EmailService::new(state.config.email.clone());
        if let Err(e) = email_service
            .send_password_reset_email(&user.email, &token)
            .await
        {
            tracing::error!("Failed to send password reset email: {:?}", e);
        }
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "If an account exists with that email, a reset link has been sent."
    })))
}

/// Reset password using a reset token
#[utoipa::path(
    post,
    path = "/api/v1/auth/reset-password",
    tag = "auth",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successfully"),
        (status = 400, description = "Invalid or expired token"),
    )
)]
pub async fn reset_password(
    state: web::Data<AppState>,
    body: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    validate_password_strength(&body.new_password).map_err(|e| AppError::BadRequest(e))?;

    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires_at > NOW() AND is_active = true"
    )
    .bind(&body.token)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("Invalid or expired password reset token".into()))?;

    let new_hash = hash_password(&body.new_password)?;

    // Update password and clear the reset token
    sqlx::query(
        "UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires_at = NULL, updated_at = NOW() WHERE id = $2"
    )
    .bind(&new_hash)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    // Revoke all existing sessions for security
    sqlx::query("UPDATE sessions SET is_revoked = true WHERE user_id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await?;

    tracing::info!("Password reset for user: {}", user.email);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Password reset successfully. Please log in with your new password."
    })))
}

/// Verify email address with a token
#[utoipa::path(
    get,
    path = "/api/v1/auth/verify-email",
    tag = "auth",
    params(
        ("token" = String, Query, description = "Email verification token")
    ),
    responses(
        (status = 200, description = "Email verified"),
        (status = 400, description = "Invalid or expired token"),
    )
)]
pub async fn verify_email(
    state: web::Data<AppState>,
    query: web::Query<VerifyEmailRequest>,
) -> Result<HttpResponse, AppError> {
    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE email_verification_token = $1 AND email_verification_expires_at > NOW()"
    )
    .bind(&query.token)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("Invalid or expired verification token".into()))?;

    sqlx::query(
        "UPDATE users SET is_email_verified = true, email_verification_token = NULL, email_verification_expires_at = NULL, updated_at = NOW() WHERE id = $1"
    )
    .bind(user.id)
    .execute(&state.db)
    .await?;

    tracing::info!("Email verified for user: {}", user.email);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Email verified successfully. You can now log in."
    })))
}

/// Resend verification email
#[utoipa::path(
    post,
    path = "/api/v1/auth/resend-verification",
    tag = "auth",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 200, description = "Verification email sent"),
    )
)]
pub async fn resend_verification(
    state: web::Data<AppState>,
    body: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE email = $1 AND is_active = true AND is_email_verified = false",
    )
    .bind(&body.email.to_lowercase())
    .fetch_optional(&state.db)
    .await?;

    if let Some(user) = user {
        let token = generate_secure_token(64);
        let expiry =
            Utc::now() + Duration::minutes(state.config.security.email_token_expiry_minutes);

        sqlx::query(
            "UPDATE users SET email_verification_token = $1, email_verification_expires_at = $2, updated_at = NOW() WHERE id = $3"
        )
        .bind(&token)
        .bind(expiry)
        .bind(user.id)
        .execute(&state.db)
        .await?;

        let email_service = EmailService::new(state.config.email.clone());
        let name = user.display_name.as_deref().unwrap_or(&user.email);
        let _ = email_service
            .send_verification_email(&user.email, name, &token)
            .await;
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "If an unverified account exists with that email, a new verification link has been sent."
    })))
}
