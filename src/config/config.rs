use eyre::{Result, WrapErr};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Max failed login attempts before account lockout
    pub max_login_attempts: u32,
    /// How many minutes to lock an account after too many failures
    pub lockout_duration_minutes: i64,
    /// How many minutes an email verification token is valid
    pub email_token_expiry_minutes: i64,
    /// How many minutes a password reset token is valid
    pub password_reset_expiry_minutes: i64,
    /// Require email verification before login
    pub require_email_verification: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthConfig {
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_uri: String,
    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub from_address: String,
    pub from_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// Secret used to sign access tokens
    pub access_secret: String,
    /// Secret used to sign refresh tokens
    pub refresh_secret: String,
    /// How many minutes until an access token expires
    pub access_expiry_minutes: i64,
    /// How many days until a refresh token expires
    pub refresh_expiry_days: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub base_url: String,
}

/// AppConfig holds every setting the app needs.
/// Values come from environment variables or a .env file.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub email: EmailConfig,
    pub oauth: OAuthConfig,
    pub security: SecurityConfig,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        Ok(AppConfig {
            server: ServerConfig {
                host: std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
                port: std::env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".into())
                    .parse()
                    .wrap_err("Invalid SERVER_PORT")?,
                base_url: std::env::var("BASE_URL")
                    .unwrap_or_else(|_| "http://localhost:8080".into()),
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL").wrap_err("DATABASE_URL must be set")?,
                max_connections: std::env::var("DATABASE_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".into())
                    .parse()
                    .unwrap_or(10),
            },
            jwt: JwtConfig {
                access_secret: std::env::var("JWT_ACCESS_SECRET")
                    .wrap_err("JWT_ACCESS_SECRET must be set")?,
                refresh_secret: std::env::var("JWT_REFRESH_SECRET")
                    .wrap_err("JWT_REFRESH_SECRET must be set")?,
                access_expiry_minutes: std::env::var("JWT_ACCESS_EXPIRY_MINUTES")
                    .unwrap_or_else(|_| "15".into())
                    .parse()
                    .unwrap_or(15),
                refresh_expiry_days: std::env::var("JWT_REFRESH_EXPIRY_DAYS")
                    .unwrap_or_else(|_| "30".into())
                    .parse()
                    .unwrap_or(30),
            },
            email: EmailConfig {
                smtp_host: std::env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".into()),
                smtp_port: std::env::var("SMTP_PORT")
                    .unwrap_or_else(|_| "587".into())
                    .parse()
                    .unwrap_or(587),
                smtp_user: std::env::var("SMTP_USER").unwrap_or_default(),
                smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
                from_address: std::env::var("EMAIL_FROM")
                    .unwrap_or_else(|_| "noreply@example.com".into()),
                from_name: std::env::var("EMAIL_FROM_NAME").unwrap_or_else(|_| "RustAuth".into()),
            },
            oauth: OAuthConfig {
                github_client_id: std::env::var("GITHUB_CLIENT_ID").unwrap_or_default(),
                github_client_secret: std::env::var("GITHUB_CLIENT_SECRET").unwrap_or_default(),
                github_redirect_uri: std::env::var("GITHUB_REDIRECT_URI").unwrap_or_else(|_| {
                    "http://localhost:8080/api/v1/oauth/github/callback".into()
                }),
                google_client_id: std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
                google_client_secret: std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
                google_redirect_uri: std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| {
                    "http://localhost:8080/api/v1/oauth/google/callback".into()
                }),
            },
            security: SecurityConfig {
                max_login_attempts: std::env::var("MAX_LOGIN_ATTEMPTS")
                    .unwrap_or_else(|_| "5".into())
                    .parse()
                    .unwrap_or(5),
                lockout_duration_minutes: std::env::var("LOCKOUT_DURATION_MINUTES")
                    .unwrap_or_else(|_| "30".into())
                    .parse()
                    .unwrap_or(30),
                email_token_expiry_minutes: std::env::var("EMAIL_TOKEN_EXPIRY_MINUTES")
                    .unwrap_or_else(|_| "1440".into()) // 24 hours
                    .parse()
                    .unwrap_or(1440),
                password_reset_expiry_minutes: std::env::var("PASSWORD_RESET_EXPIRY_MINUTES")
                    .unwrap_or_else(|_| "60".into())
                    .parse()
                    .unwrap_or(60),
                require_email_verification: std::env::var("REQUIRE_EMAIL_VERIFICATION")
                    .unwrap_or_else(|_| "true".into())
                    == "true",
            },
        })
    }
}
