use actix_web::{FromRequest, HttpRequest, dev::Payload, web};
use futures_util::future::{Ready, ready};
use uuid::Uuid;

use crate::models::user::UserRole;
use crate::services::AppState;
use crate::utils::errors::AppError;
use crate::utils::jwt::{extract_bearer_token, verify_access_token};

/// AuthenticatedUser is "extracted" from every protected request.
/// When you add it as a parameter to a handler, actix-web automatically
/// checks the Authorization header and verifies the JWT.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub role: UserRole,
    pub is_email_verified: bool,
}

impl FromRequest for AuthenticatedUser {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Try to get the Authorization header
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok());
        let token = match extract_bearer_token(auth_header) {
            Some(t) => t,
            None => {
                return ready(Err(AppError::Unauthorized(
                    "No authorization token provided".into(),
                )));
            }
        };

        // Get the JWT secret from app state
        let state = match req.app_data::<web::Data<AppState>>() {
            Some(s) => s,
            None => return ready(Err(AppError::Internal("App state not available".into()))),
        };

        // Verify the token
        match verify_access_token(token, &state.config.jwt.access_secret) {
            Ok(claims) => {
                if claims.token_type != "access" {
                    return ready(Err(AppError::Unauthorized("Invalid token type".into())));
                }
                let user_id = match Uuid::parse_str(&claims.sub) {
                    Ok(id) => id,
                    Err(_) => {
                        return ready(Err(AppError::Unauthorized(
                            "Invalid user ID in token".into(),
                        )));
                    }
                };

                ready(Ok(AuthenticatedUser {
                    user_id,
                    role: claims.role,
                    is_email_verified: claims.is_email_verified,
                }))
            }
            Err(e) => ready(Err(e)),
        }
    }
}
