use actix_web::{HttpRequest, HttpResponse, web};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    middleware::auth::AuthenticatedUser,
    models::{oauth::OAuthUserInfo, user::PublicUser},
    services::{AppState, EmailService},
    utils::{
        errors::AppError,
        jwt::{create_access_token, create_refresh_token},
        totp::generate_secure_token,
    },
};

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuthRedirectResponse {
    pub redirect_url: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LinkProviderRequest {
    pub provider: String,
    pub code: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UnlinkProviderRequest {
    pub provider: String,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/oauth")
            .route("/github", web::get().to(github_login))
            .route("/github/callback", web::get().to(github_callback))
            .route("/google", web::get().to(google_login))
            .route("/google/callback", web::get().to(google_callback))
            .route("/link", web::post().to(link_provider))
            .route("/unlink", web::post().to(unlink_provider))
            .route("/providers", web::get().to(list_providers)),
    );
}

/// Initiate GitHub OAuth login - returns a redirect URL
#[utoipa::path(
    get,
    path = "/api/v1/oauth/github",
    tag = "oauth",
    responses(
        (status = 200, description = "GitHub OAuth redirect URL", body = OAuthRedirectResponse),
    )
)]
pub async fn github_login(state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let state_token = generate_secure_token(32);
    let redirect_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
        state.config.oauth.github_client_id,
        urlencoding::encode(&state.config.oauth.github_redirect_uri),
        state_token
    );

    Ok(HttpResponse::Ok().json(OAuthRedirectResponse { redirect_url }))
}

/// Handle the GitHub OAuth callback after user approves
#[utoipa::path(
    get,
    path = "/api/v1/oauth/github/callback",
    tag = "oauth",
    params(
        ("code" = String, Query, description = "OAuth authorization code from GitHub"),
        ("state" = Option<String>, Query, description = "State token for CSRF protection"),
    ),
    responses(
        (status = 200, description = "OAuth login successful"),
        (status = 400, description = "OAuth error"),
    )
)]
pub async fn github_callback(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<OAuthCallbackQuery>,
) -> Result<HttpResponse, AppError> {
    // Exchange code for access token
    let token_response = exchange_github_code(
        &query.code,
        &state.config.oauth.github_client_id,
        &state.config.oauth.github_client_secret,
    )
    .await?;

    // Get the user info from GitHub
    let user_info = get_github_user_info(&token_response.access_token).await?;

    // Login or register the user
    handle_oauth_login(&state, &req, "github", user_info).await
}

/// Initiate Google OAuth login
#[utoipa::path(
    get,
    path = "/api/v1/oauth/google",
    tag = "oauth",
    responses(
        (status = 200, description = "Google OAuth redirect URL", body = OAuthRedirectResponse),
    )
)]
pub async fn google_login(state: web::Data<AppState>) -> Result<HttpResponse, AppError> {
    let state_token = generate_secure_token(32);
    let redirect_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}",
        state.config.oauth.google_client_id,
        urlencoding::encode(&state.config.oauth.google_redirect_uri),
        state_token
    );

    Ok(HttpResponse::Ok().json(OAuthRedirectResponse { redirect_url }))
}

/// Handle the Google OAuth callback
#[utoipa::path(
    get,
    path = "/api/v1/oauth/google/callback",
    tag = "oauth",
    params(
        ("code" = String, Query, description = "OAuth authorization code from Google"),
        ("state" = Option<String>, Query, description = "State token for CSRF protection"),
    ),
    responses(
        (status = 200, description = "OAuth login successful"),
    )
)]
pub async fn google_callback(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<OAuthCallbackQuery>,
) -> Result<HttpResponse, AppError> {
    let token_response = exchange_google_code(
        &query.code,
        &state.config.oauth.google_client_id,
        &state.config.oauth.google_client_secret,
        &state.config.oauth.google_redirect_uri,
    )
    .await?;

    let user_info = get_google_user_info(&token_response.access_token).await?;

    handle_oauth_login(&state, &req, "google", user_info).await
}

/// Link an OAuth provider to the current account
#[utoipa::path(
    post,
    path = "/api/v1/oauth/link",
    tag = "oauth",
    security(("bearer_auth" = [])),
    request_body = LinkProviderRequest,
    responses(
        (status = 200, description = "Provider linked"),
        (status = 400, description = "Provider already linked"),
    )
)]
pub async fn link_provider(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<LinkProviderRequest>,
) -> Result<HttpResponse, AppError> {
    // Check if already linked
    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM oauth_providers WHERE user_id = $1 AND provider = $2",
    )
    .bind(auth_user.user_id)
    .bind(&body.provider)
    .fetch_one(&state.db)
    .await?;

    if existing > 0 {
        return Err(AppError::BadRequest(format!(
            "{} is already linked to your account",
            body.provider
        )));
    }

    // Exchange the code and get user info from the provider
    let user_info = match body.provider.as_str() {
        "github" => {
            let token = exchange_github_code(
                &body.code,
                &state.config.oauth.github_client_id,
                &state.config.oauth.github_client_secret,
            )
            .await?;
            get_github_user_info(&token.access_token).await?
        }
        "google" => {
            let token = exchange_google_code(
                &body.code,
                &state.config.oauth.google_client_id,
                &state.config.oauth.google_client_secret,
                &state.config.oauth.google_redirect_uri,
            )
            .await?;
            get_google_user_info(&token.access_token).await?
        }
        _ => return Err(AppError::BadRequest("Unsupported provider".into())),
    };

    sqlx::query(
        "INSERT INTO oauth_providers (id, user_id, provider, provider_user_id, access_token, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())"
    )
    .bind(Uuid::new_v4())
    .bind(auth_user.user_id)
    .bind(&body.provider)
    .bind(&user_info.provider_user_id)
    .bind(&user_info.access_token)
    .execute(&state.db)
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("{} linked successfully", body.provider)
    })))
}

/// Unlink an OAuth provider from the current account
#[utoipa::path(
    post,
    path = "/api/v1/oauth/unlink",
    tag = "oauth",
    security(("bearer_auth" = [])),
    request_body = UnlinkProviderRequest,
    responses(
        (status = 200, description = "Provider unlinked"),
        (status = 400, description = "Cannot unlink - no password set"),
    )
)]
pub async fn unlink_provider(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
    body: web::Json<UnlinkProviderRequest>,
) -> Result<HttpResponse, AppError> {
    // Count providers + check if password exists
    let user = sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_one(&state.db)
        .await?;

    let provider_count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oauth_providers WHERE user_id = $1")
            .bind(auth_user.user_id)
            .fetch_one(&state.db)
            .await?;

    // Safety check: make sure they can still log in another way
    if provider_count <= 1 && user.password_hash.is_none() {
        return Err(AppError::BadRequest(
            "Cannot unlink your only login method. Set a password first.".into(),
        ));
    }

    sqlx::query("DELETE FROM oauth_providers WHERE user_id = $1 AND provider = $2")
        .bind(auth_user.user_id)
        .bind(&body.provider)
        .execute(&state.db)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("{} unlinked from your account", body.provider)
    })))
}

/// List all OAuth providers linked to the current account
pub async fn list_providers(
    state: web::Data<AppState>,
    auth_user: AuthenticatedUser,
) -> Result<HttpResponse, AppError> {
    let providers = sqlx::query!(
        "SELECT provider, created_at FROM oauth_providers WHERE user_id = $1",
        auth_user.user_id
    )
    .fetch_all(&state.db)
    .await?;

    let result: Vec<_> = providers
        .iter()
        .map(|p| serde_json::json!({ "provider": p.provider, "linked_at": p.created_at }))
        .collect();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "data": result
    })))
}

// ---- Private helpers ----

#[derive(Debug, Deserialize)]
struct GithubTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct GithubUserResponse {
    id: i64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
    login: String,
}

#[derive(Debug, Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

async fn exchange_github_code(
    code: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<GithubTokenResponse, AppError> {
    let client = reqwest_client()?;
    let resp = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
        }))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("GitHub OAuth request failed: {}", e)))?;

    resp.json::<GithubTokenResponse>()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse GitHub token response: {}", e)))
}

async fn get_github_user_info(access_token: &str) -> Result<OAuthUserInfo, AppError> {
    let client = reqwest_client()?;

    let user: GithubUserResponse = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", access_token))
        .header("User-Agent", "RustAuth/1.0")
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("GitHub user API failed: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse GitHub user: {}", e)))?;

    // Get the primary email if not public
    let email = if user.email.is_some() {
        user.email
    } else {
        let emails: Vec<GithubEmail> = client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "RustAuth/1.0")
            .send()
            .await
            .map_err(|e| AppError::Internal(format!("GitHub emails API failed: {}", e)))?
            .json()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to parse GitHub emails: {}", e)))?;

        emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .map(|e| e.email)
    };

    Ok(OAuthUserInfo {
        provider_user_id: user.id.to_string(),
        email,
        display_name: user.name.or(Some(user.login)),
        avatar_url: user.avatar_url,
        access_token: access_token.to_string(),
        refresh_token: None,
    })
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoogleUserResponse {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
}

async fn exchange_google_code(
    code: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<GoogleTokenResponse, AppError> {
    let client = reqwest_client()?;
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .json(&serde_json::json!({
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Google OAuth request failed: {}", e)))?;

    resp.json::<GoogleTokenResponse>()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse Google token: {}", e)))
}

async fn get_google_user_info(access_token: &str) -> Result<OAuthUserInfo, AppError> {
    let client = reqwest_client()?;

    let user: GoogleUserResponse = client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Google user API failed: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to parse Google user: {}", e)))?;

    Ok(OAuthUserInfo {
        provider_user_id: user.sub,
        email: user.email,
        display_name: user.name,
        avatar_url: user.picture,
        access_token: access_token.to_string(),
        refresh_token: None,
    })
}

/// The core OAuth login/register logic:
/// 1. If provider already linked → log in as that user
/// 2. If email exists → link provider and log in
/// 3. Otherwise → create new account and log in
async fn handle_oauth_login(
    state: &web::Data<AppState>,
    req: &HttpRequest,
    provider: &str,
    info: OAuthUserInfo,
) -> Result<HttpResponse, AppError> {
    // 1. Check if this OAuth provider ID is already linked to an account
    let existing_provider = sqlx::query!(
        "SELECT user_id FROM oauth_providers WHERE provider = $1 AND provider_user_id = $2",
        provider,
        info.provider_user_id
    )
    .fetch_optional(&state.db)
    .await?;

    let user_id = if let Some(record) = existing_provider {
        // Already linked, just log in
        record.user_id
    } else if let Some(ref email) = info.email {
        // Check if a user with this email already exists
        let existing_user = sqlx::query!(
            "SELECT id FROM users WHERE email = $1 AND is_active = true",
            email.to_lowercase()
        )
        .fetch_optional(&state.db)
        .await?;

        if let Some(existing) = existing_user {
            // Link this provider to the existing account
            sqlx::query(
                "INSERT INTO oauth_providers (id, user_id, provider, provider_user_id, access_token, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())"
            )
            .bind(Uuid::new_v4())
            .bind(existing.id)
            .bind(provider)
            .bind(&info.provider_user_id)
            .bind(&info.access_token)
            .execute(&state.db)
            .await?;
            existing.id
        } else {
            // Create a new account
            create_oauth_user(state, provider, &info).await?
        }
    } else {
        // No email from provider - create user without email
        create_oauth_user(state, provider, &info).await?
    };

    // Fetch the user record
    let user = sqlx::query_as::<_, crate::models::user::User>(
        "SELECT * FROM users WHERE id = $1 AND is_active = true",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Account not found or inactive".into()))?;

    // Update last login
    let ip = get_client_ip(req);
    sqlx::query("UPDATE users SET last_login_at = NOW(), last_login_ip = $1, updated_at = NOW() WHERE id = $2")
        .bind(&ip)
        .bind(user.id)
        .execute(&state.db)
        .await?;

    // Create session
    let session_id = Uuid::new_v4();
    let ip_str = ip.clone();
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let refresh_expiry = chrono::Duration::days(state.config.jwt.refresh_expiry_days);
    let expires_at = Utc::now() + refresh_expiry;

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

    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, user_agent, ip_address, is_oauth, oauth_provider, expires_at, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, true, $6, $7, NOW(), NOW())"
    )
    .bind(session_id)
    .bind(user.id)
    .bind(refresh_token.len().to_string())
    .bind(&user_agent)
    .bind(&ip_str)
    .bind(provider)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    tracing::info!("OAuth login via {}: user {}", provider, user.id);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": state.config.jwt.access_expiry_minutes * 60,
        "user": PublicUser::from(user),
    })))
}

async fn create_oauth_user(
    state: &web::Data<AppState>,
    provider: &str,
    info: &OAuthUserInfo,
) -> Result<Uuid, AppError> {
    let user_id = Uuid::new_v4();
    let email = info
        .email
        .clone()
        .unwrap_or_else(|| format!("{}_{}", provider, info.provider_user_id));

    // OAuth users are auto-verified since the provider already verified their email
    sqlx::query(
        "INSERT INTO users (id, email, display_name, avatar_url, is_email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, true, NOW(), NOW())"
    )
    .bind(user_id)
    .bind(email.to_lowercase())
    .bind(&info.display_name)
    .bind(&info.avatar_url)
    .execute(&state.db)
    .await?;

    sqlx::query(
        "INSERT INTO oauth_providers (id, user_id, provider, provider_user_id, access_token, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())"
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(provider)
    .bind(&info.provider_user_id)
    .bind(&info.access_token)
    .execute(&state.db)
    .await?;

    // Send welcome email
    if let Some(ref email_addr) = info.email {
        let email_service = EmailService::new(state.config.email.clone());
        // let name = info.display_name.as_deref().unwrap_or("there");
        let _ = email_service
            .send_security_alert(
                email_addr,
                "New account created",
                &format!("Your account was created via {} login.", provider),
            )
            .await;
    }

    Ok(user_id)
}

fn get_client_ip(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("X-Forwarded-For")
        .or_else(|| req.headers().get("X-Real-IP"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        .or_else(|| req.peer_addr().map(|a| a.ip().to_string()))
}

fn reqwest_client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build HTTP client: {}", e)))
}
