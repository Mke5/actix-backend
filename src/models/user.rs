use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// The role of a user in the system
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq, ToSchema)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    /// Regular user
    User,
    /// Can manage users and view admin panel
    Admin,
    /// Full system access
    SuperAdmin,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

/// Full user model - only used internally, never sent directly to clients
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    /// The hashed password (never expose this!)
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub is_email_verified: bool,
    /// The verification token sent to email
    #[serde(skip_serializing)]
    pub email_verification_token: Option<String>,
    pub email_verification_expires_at: Option<DateTime<Utc>>,
    /// Token for resetting password
    #[serde(skip_serializing)]
    pub password_reset_token: Option<String>,
    pub password_reset_expires_at: Option<DateTime<Utc>>,
    /// Number of failed login attempts
    pub failed_login_attempts: i32,
    /// When the account gets unlocked (null = not locked)
    pub locked_until: Option<DateTime<Utc>>,
    /// Is TOTP (authenticator app) enabled?
    pub totp_enabled: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    /// Backup codes for when you lose your authenticator app
    #[serde(skip_serializing)]
    pub totp_backup_codes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
}

/// The safe version of User - this is what gets sent to API clients
/// We hide things like password hashes and secret tokens
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublicUser {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub role: UserRole,
    pub is_active: bool,
    pub is_email_verified: bool,
    pub totp_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl From<User> for PublicUser {
    fn from(user: User) -> Self {
        PublicUser {
            id: user.id,
            email: user.email,
            username: user.username,
            display_name: user.display_name,
            avatar_url: user.avatar_url,
            role: user.role,
            is_active: user.is_active,
            is_email_verified: user.is_email_verified,
            totp_enabled: user.totp_enabled,
            created_at: user.created_at,
            updated_at: user.updated_at,
            last_login_at: user.last_login_at,
        }
    }
}

impl User {
    /// Check if the account is currently locked
    pub fn is_locked(&self) -> bool {
        if let Some(locked_until) = self.locked_until {
            locked_until > Utc::now()
        } else {
            false
        }
    }
}
