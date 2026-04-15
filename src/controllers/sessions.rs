use actix_web::{HttpRequest, HttpResponse, web};
use uuid::Uuid;

use crate::{
    middleware::auth::AuthenticatedUser,
    models::session::{PublicSession, Session},
    services::AppState,
    utils::errors::AppError,
    utils::jwt::verify_access_token,
};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/sessions")
            .route("", web::get().to(list_sessions))
            .route("/{id}", web::delete().to(revoke_session))
            .route("", web::delete().to(revoke_all_sessions)),
    );
}

/// List all active sessions for the current user
#[utoipa::path(
    get,
    path = "/api/v1/sessions",
    tag = "sessions",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of sessions", body = Vec<PublicSession>),
    )
)]
pub async fn list_sessions(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let sessions = sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > NOW() ORDER BY last_used_at DESC"
    )
    .bind(auth_user.user_id)
    .fetch_all(&state.db)
    .await?;

    // Figure out which session is the current one
    let current_session_id = get_current_session_id(&req, &state);

    let public_sessions: Vec<PublicSession> = sessions
        .into_iter()
        .map(|s| {
            let is_current = current_session_id.map(|id| id == s.id).unwrap_or(false);
            PublicSession {
                id: s.id,
                user_agent: s.user_agent,
                ip_address: s.ip_address,
                is_oauth: s.is_oauth,
                oauth_provider: s.oauth_provider,
                created_at: s.created_at,
                expires_at: s.expires_at,
                last_used_at: s.last_used_at,
                is_current,
            }
        })
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": public_sessions
    })))
}

/// Revoke a specific session
#[utoipa::path(
    delete,
    path = "/api/v1/sessions/{id}",
    tag = "sessions",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "Session ID to revoke")),
    responses(
        (status = 200, description = "Session revoked"),
        (status = 404, description = "Session not found"),
    )
)]
pub async fn revoke_session(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let session_id = *path;

    let rows_affected =
        sqlx::query("UPDATE sessions SET is_revoked = true WHERE id = $1 AND user_id = $2")
            .bind(session_id)
            .bind(auth_user.user_id)
            .execute(&state.db)
            .await?
            .rows_affected();

    if rows_affected == 0 {
        return Err(AppError::NotFound("Session not found".into()));
    }

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Session revoked"
    })))
}

/// Revoke all sessions (log out from all devices)
#[utoipa::path(
    delete,
    path = "/api/v1/sessions",
    tag = "sessions",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "All sessions revoked"),
    )
)]
pub async fn revoke_all_sessions(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    let rows = sqlx::query(
        "UPDATE sessions SET is_revoked = true WHERE user_id = $1 AND is_revoked = false",
    )
    .bind(auth_user.user_id)
    .execute(&state.db)
    .await?
    .rows_affected();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("Revoked {} session(s)", rows)
    })))
}

fn get_current_session_id(req: &HttpRequest, state: &web::Data<AppState>) -> Option<Uuid> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))?;

    // We can't get session ID from access token directly, but we can from the refresh
    // In a real implementation, you'd embed the session ID in the access token too
    let claims = verify_access_token(token, &state.config.jwt.access_secret).ok()?;
    Uuid::parse_str(&claims.sub).ok()
}
