use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

/// AppError is the single error type for the whole application.
/// Every error that can happen gets turned into one of these variants.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "error", content = "message")]
pub enum AppError {
    /// The request was missing something or had invalid data
    BadRequest(String),
    /// The user is not logged in
    Unauthorized(String),
    /// The user is logged in but not allowed to do this
    Forbidden(String),
    /// The thing they're looking for doesn't exist
    NotFound(String),
    /// Someone is sending too many requests too fast
    TooManyRequests(String),
    /// The account has been locked due to too many failed logins
    AccountLocked(String),
    /// The email has not been verified yet
    EmailNotVerified,
    /// Multi-factor auth code is required
    MfaRequired,
    /// Something went wrong on the server
    Internal(String),
    /// Database error
    Database(String),
    /// Validation error from request data
    Validation(Vec<String>),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppError::TooManyRequests(msg) => write!(f, "Too many requests: {}", msg),
            AppError::AccountLocked(msg) => write!(f, "Account locked: {}", msg),
            AppError::EmailNotVerified => write!(f, "Email not verified"),
            AppError::MfaRequired => write!(f, "MFA code required"),
            AppError::Internal(msg) => write!(f, "Internal error: {}", msg),
            AppError::Database(msg) => write!(f, "Database error: {}", msg),
            AppError::Validation(errs) => write!(f, "Validation errors: {}", errs.join(", ")),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let body = serde_json::json!({
            "success": false,
            "error": self.error_code(),
            "message": self.to_string(),
        });

        match self {
            AppError::BadRequest(_) | AppError::Validation(_) => {
                HttpResponse::BadRequest().json(body)
            }
            AppError::Unauthorized(_) => HttpResponse::Unauthorized().json(body),
            AppError::Forbidden(_) => HttpResponse::Forbidden().json(body),
            AppError::NotFound(_) => HttpResponse::NotFound().json(body),
            AppError::TooManyRequests(_) => HttpResponse::TooManyRequests().json(body),
            AppError::AccountLocked(_) => HttpResponse::Forbidden().json(body),
            AppError::EmailNotVerified => HttpResponse::Forbidden().json(body),
            AppError::MfaRequired => HttpResponse::Unauthorized().json(serde_json::json!({
                "success": false,
                "error": "MFA_REQUIRED",
                "message": "Multi-factor authentication code required",
                "mfa_required": true,
            })),
            AppError::Internal(_) | AppError::Database(_) => {
                HttpResponse::InternalServerError().json(body)
            }
        }
    }
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::BadRequest(_) => "BAD_REQUEST",
            AppError::Unauthorized(_) => "UNAUTHORIZED",
            AppError::Forbidden(_) => "FORBIDDEN",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::TooManyRequests(_) => "TOO_MANY_REQUESTS",
            AppError::AccountLocked(_) => "ACCOUNT_LOCKED",
            AppError::EmailNotVerified => "EMAIL_NOT_VERIFIED",
            AppError::MfaRequired => "MFA_REQUIRED",
            AppError::Internal(_) => "INTERNAL_ERROR",
            AppError::Database(_) => "DATABASE_ERROR",
            AppError::Validation(_) => "VALIDATION_ERROR",
        }
    }
}

// Convert sqlx errors into AppError automatically
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Resource not found".into()),
            _ => {
                tracing::error!("Database error: {:?}", e);
                AppError::Database(e.to_string())
            }
        }
    }
}

// Convert validator errors into AppError
impl From<validator::ValidationErrors> for AppError {
    fn from(e: validator::ValidationErrors) -> Self {
        let messages: Vec<String> = e
            .field_errors()
            .iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |err| {
                    format!(
                        "{}: {}",
                        field,
                        err.message
                            .as_ref()
                            .map(|m| m.as_ref())
                            .unwrap_or("invalid value")
                    )
                })
            })
            .collect();
        AppError::Validation(messages)
    }
}
