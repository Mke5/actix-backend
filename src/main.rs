use actix_cors::Cors;
use actix_web::{App, HttpServer, middleware::Logger, web};
use color_eyre::Result;
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use utoipa::OpenApi;
use utoipa_redoc::{Redoc, Servable};
use utoipa_swagger_ui::SwaggerUi;

mod config;
mod controllers;
mod middleware;
mod models;
mod services;
mod utils;

use config::config::AppConfig;
use controllers::{auth, mfa, oauth, sessions, users};

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::register,
        auth::login,
        auth::logout,
        auth::refresh_token,
        auth::forgot_password,
        auth::reset_password,
        auth::verify_email,
        auth::resend_verification,
        users::get_me,
        users::update_me,
        users::delete_me,
        users::change_password,
        users::list_users,
        users::get_user,
        users::update_user,
        users::delete_user,
        sessions::list_sessions,
        sessions::revoke_session,
        sessions::revoke_all_sessions,
        mfa::setup_totp,
        mfa::confirm_totp,
        mfa::disable_totp,
        mfa::verify_totp,
        mfa::generate_backup_codes,
        oauth::github_login,
        oauth::github_callback,
        oauth::google_login,
        oauth::google_callback,
        oauth::link_provider,
        oauth::unlink_provider,
    ),
    components(
        schemas(
            models::user::User,
            models::user::PublicUser,
            models::user::UserRole,
            models::session::Session,
            controllers::auth::RegisterRequest,
            controllers::auth::LoginRequest,
            controllers::auth::ForgotPasswordRequest,
            controllers::auth::ResetPasswordRequest,
            controllers::auth::VerifyEmailRequest,
            controllers::auth::RefreshTokenRequest,
            controllers::auth::AuthResponse,
            controllers::users::UpdateUserRequest,
            controllers::users::ChangePasswordRequest,
            controllers::mfa::SetupTotpResponse,
            controllers::mfa::ConfirmTotpRequest,
            controllers::mfa::VerifyTotpRequest,
            controllers::mfa::BackupCodesResponse,
            utils::errors::AppError,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "users", description = "User management endpoints"),
        (name = "sessions", description = "Session management endpoints"),
        (name = "mfa", description = "Multi-factor authentication"),
        (name = "oauth", description = "OAuth2 social login"),
    ),
    info(
        title = "RustAuth API",
        version = "1.0.0",
        description = "A production-ready authentication service built with Rust and Actix-Web",
        contact(name = "RustAuth", url = "https://github.com/your-org/rustauth"),
        license(name = "MIT"),
    )
)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> Result<()> {
    // Load .env file first
    dotenv().ok();

    // Initialize color-eyre for beautiful error reports
    color_eyre::install()?;

    // Initialize tracing/logging
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rustauth=debug,actix_web=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = AppConfig::from_env()?;
    tracing::info!("Configuration loaded");

    // Create database connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&config.database.url)
        .await?;

    tracing::info!("Database connected");

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;
    tracing::info!("Migrations applied");

    // Shared app state
    let app_state = web::Data::new(services::AppState::new(db_pool, config.clone()));
    let openapi = ApiDoc::openapi();
    let host = config.server.host.clone();
    let port = config.server.port;

    tracing::info!("Starting server on {}:{}", host, port);
    HttpServer::new(move || {
        // CORS configuration
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                // In production, restrict to known origins
                origin.as_bytes().starts_with(b"http://localhost")
                    || origin.as_bytes().starts_with(b"https://")
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .max_age(3600);

        App::new()
            .app_data(app_state.clone())
            .wrap(cors)
            .wrap(Logger::default())
            // API v1 routes
            .service(
                web::scope("/api/v1")
                    .configure(auth::configure)
                    .configure(users::configure)
                    .configure(sessions::configure)
                    .configure(mfa::configure)
                    .configure(oauth::configure),
            )
            // Health check
            .route("/health", web::get().to(health_check))
            // API Documentation
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
            )
            .service(Redoc::with_url("/redoc", openapi.clone()))
    })
    .bind((host.as_str(), port))?
    .run()
    .await?;
    Ok(())
}

async fn health_check() -> actix_web::HttpResponse {
    actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "service": "rustauth"
    }))
}
