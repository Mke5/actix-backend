use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::{
    middleware::auth::{AdminUser, AuthenticatedUser},
    models::user::{PublicUser, UserRole},
    services::AppState,
    utils::errors::AppError,
    utils::password::{hash_password, validate_password_strength, verify_password},
};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateUserRequest {
    #[validate(length(min = 2, max = 50))]
    pub display_name: Option<String>,
    #[validate(length(min = 3, max = 30))]
    pub username: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AdminUpdateUserRequest {
    pub role: Option<UserRole>,
    pub is_active: Option<bool>,
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaginatedUsers {
    pub users: Vec<PublicUser>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/me", web::get().to(get_me))
            .route("/me", web::patch().to(update_me))
            .route("/me", web::delete().to(delete_me))
            .route("/me/password", web::put().to(change_password))
            // Admin-only routes
            .route("", web::get().to(list_users))
            .route("/{id}", web::get().to(get_user))
            .route("/{id}", web::patch().to(update_user))
            .route("/{id}", web::delete().to(delete_user)),
    );
}

/// Get the currently authenticated user's profile
#[utoipa::path(
    get,
    path = "/api/v1/users/me",
    tag = "users",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User profile", body = PublicUser),
        (status = 401, description = "Not authenticated"),
    )
)]
pub async fn get_me(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    let user = sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": PublicUser::from(user)
    })))
}

/// Update the current user's profile
#[utoipa::path(
    patch,
    path = "/api/v1/users/me",
    tag = "users",
    security(("bearer_auth" = [])),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "Profile updated", body = PublicUser),
        (status = 400, description = "Validation error"),
    )
)]
pub async fn update_me(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    // Check username uniqueness if changing it
    if let Some(ref username) = body.username {
        let taken = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE username = $1 AND id != $2",
        )
        .bind(username)
        .bind(auth_user.user_id)
        .fetch_one(&state.db)
        .await?;

        if taken > 0 {
            return Err(AppError::BadRequest("Username is already taken".into()));
        }
    }

    let user = sqlx::query_as::<_, crate::models::user::User>(
        r#"
        UPDATE users
        SET
            display_name = COALESCE($1, display_name),
            username = COALESCE($2, username),
            avatar_url = COALESCE($3, avatar_url),
            updated_at = NOW()
        WHERE id = $4
        RETURNING *
        "#,
    )
    .bind(&body.display_name)
    .bind(&body.username)
    .bind(&body.avatar_url)
    .bind(auth_user.user_id)
    .fetch_one(&state.db)
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": PublicUser::from(user)
    })))
}

/// Delete the current user's account
#[utoipa::path(
    delete,
    path = "/api/v1/users/me",
    tag = "users",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Account deleted"),
    )
)]
pub async fn delete_me(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    // Soft delete - mark as inactive rather than deleting the row
    // This preserves audit trails and prevents orphaned data
    sqlx::query(
        "UPDATE users SET is_active = false, email = CONCAT('deleted_', id, '_', email), updated_at = NOW() WHERE id = $1"
    )
    .bind(auth_user.user_id)
    .execute(&state.db)
    .await?;

    // Revoke all sessions
    sqlx::query("UPDATE sessions SET is_revoked = true WHERE user_id = $1")
        .bind(auth_user.user_id)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Account deleted successfully"
    })))
}

/// Change the current user's password
#[utoipa::path(
    put,
    path = "/api/v1/users/me/password",
    tag = "users",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed"),
        (status = 400, description = "Invalid current password"),
    )
)]
pub async fn change_password(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;

    validate_password_strength(&body.new_password).map_err(|e| AppError::BadRequest(e))?;

    let user = sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_one(&state.db)
        .await?;

    // Verify current password
    let hash = user.password_hash.as_deref().unwrap_or("");
    if !verify_password(&body.current_password, hash)? {
        return Err(AppError::BadRequest("Current password is incorrect".into()));
    }

    let new_hash = hash_password(&body.new_password)?;

    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&new_hash)
        .bind(auth_user.user_id)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Password changed successfully"
    })))
}

/// List all users (Admin only)
#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "users",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<u32>, Query, description = "Page number (default: 1)"),
        ("per_page" = Option<u32>, Query, description = "Items per page (default: 20, max: 100)"),
    ),
    responses(
        (status = 200, description = "List of users", body = PaginatedUsers),
        (status = 403, description = "Admin access required"),
    )
)]
pub async fn list_users(
    state: web::Data<AppState>,
    _admin: AdminUser,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100).max(1);
    let offset = ((page - 1) * per_page) as i64;

    let total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await?;

    let users = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(per_page as i64)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let public_users: Vec<PublicUser> = users.into_iter().map(Into::into).collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": {
            "users": public_users,
            "total": total,
            "page": page,
            "per_page": per_page,
        }
    })))
}

/// Get a specific user by ID (Admin only)
#[utoipa::path(
    get,
    path = "/api/v1/users/{id}",
    tag = "users",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User details", body = PublicUser),
        (status = 404, description = "User not found"),
        (status = 403, description = "Admin access required"),
    )
)]
pub async fn get_user(
    state: web::Data<AppState>,
    _admin: AdminUser,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let user = sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
        .bind(*path)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": PublicUser::from(user)
    })))
}

/// Update a user's role or status (Admin only)
#[utoipa::path(
    patch,
    path = "/api/v1/users/{id}",
    tag = "users",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "User ID")),
    request_body = AdminUpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = PublicUser),
        (status = 404, description = "User not found"),
        (status = 403, description = "Admin access required"),
    )
)]
pub async fn update_user(
    state: web::Data<AppState>,
    admin: AdminUser,
    path: web::Path<Uuid>,
    body: web::Json<AdminUpdateUserRequest>,
) -> Result<HttpResponse, AppError> {
    let target_id = *path;

    // Super Admins cannot be modified by regular Admins
    let target =
        sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
            .bind(target_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    if matches!(target.role, UserRole::SuperAdmin) && !matches!(admin.0.role, UserRole::SuperAdmin)
    {
        return Err(AppError::Forbidden(
            "Cannot modify super admin users".into(),
        ));
    }

    let user = sqlx::query_as::<_, crate::models::user::User>(
        r#"
        UPDATE users
        SET
            role = COALESCE($1, role),
            is_active = COALESCE($2, is_active),
            display_name = COALESCE($3, display_name),
            updated_at = NOW()
        WHERE id = $4
        RETURNING *
        "#,
    )
    .bind(&body.role)
    .bind(body.is_active)
    .bind(&body.display_name)
    .bind(target_id)
    .fetch_one(&state.db)
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": PublicUser::from(user)
    })))
}

/// Delete a user (Admin only) - soft delete
#[utoipa::path(
    delete,
    path = "/api/v1/users/{id}",
    tag = "users",
    security(("bearer_auth" = [])),
    params(("id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User deleted"),
        (status = 403, description = "Admin access required"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn delete_user(
    state: web::Data<AppState>,
    admin: AdminUser,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let target_id = *path;

    // Can't delete yourself
    if target_id == admin.0.user_id {
        return Err(AppError::BadRequest(
            "Cannot delete your own account via admin API".into(),
        ));
    }

    sqlx::query("UPDATE users SET is_active = false, updated_at = NOW() WHERE id = $1")
        .bind(target_id)
        .execute(&state.db)
        .await?;

    sqlx::query("UPDATE sessions SET is_revoked = true WHERE user_id = $1")
        .bind(target_id)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "User deactivated successfully"
    })))
}
