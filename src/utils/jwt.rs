use crate::models::user::UserRole;
use crate::utils::errors::AppError;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Extract the bearer token from an Authorization header./// Expects format: "Bearer <token>"
pub fn extract_bearer_token(auth_header: Option<&str>) -> Option<&str> {
    auth_header.and_then(|header| {
        header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
    })
}

/// The data stored inside an access token.
/// "Claims" is the official JWT name for "the stuff inside the token".
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject = the user's ID
    pub sub: String,
    /// Expiry timestamp (Unix seconds)
    pub exp: i64,
    /// Issued at timestamp
    pub iat: i64,
    /// Token type so we don't mix them up
    pub token_type: String,
    pub role: UserRole,
    pub is_email_verified: bool,
}

/// The data stored inside a refresh token.
/// Simpler than access token - just enough to find the session.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub token_type: String,
    /// Which session this refresh token belongs to
    pub session_id: String,
}

pub fn create_access_token(
    user_id: Uuid,
    role: UserRole,
    is_email_verified: bool,
    secret: &str,
    expiry_minutes: i64,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    let claims = AccessTokenClaims {
        sub: user_id.to_string(),
        exp: now + (expiry_minutes * 60),
        iat: now,
        token_type: "access".to_string(),
        role,
        is_email_verified,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to create access token: {}", e)))
}

pub fn create_refresh_token(
    user_id: Uuid,
    session_id: Uuid,
    secret: &str,
    expiry_days: i64,
) -> Result<String, AppError> {
    let now = Utc::now().timestamp();
    let claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        exp: now + (expiry_days * 86400),
        iat: now,
        token_type: "refresh".to_string(),
        session_id: session_id.to_string(),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to create refresh token: {}", e)))
}

pub fn verify_access_token(token: &str, secret: &str) -> Result<AccessTokenClaims, AppError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;

    decode::<AccessTokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Unauthorized("Token expired".into())
        }
        _ => AppError::Unauthorized("Invalid token".into()),
    })
}

pub fn verify_refresh_token(token: &str, secret: &str) -> Result<RefreshTokenClaims, AppError> {
    let mut validation = Validation::default();
    validation.validate_exp = true;
    decode::<RefreshTokenClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Unauthorized("Refresh token expired".into())
        }
        _ => AppError::Unauthorized("Invalid refresh token".into()),
    })
}
