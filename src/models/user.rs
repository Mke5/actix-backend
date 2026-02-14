use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    User,
    Moderator,
    Admin,
}

impl UserRole {
    pub fn to_str(&self) -> &str {
        match self {
            UserRole::User => "user",
            UserRole::Moderator => "moderator",
            UserRole::Admin => "admin",
        }
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,

    #[serde(skip_serializing)] //select false on user sql queries for the password hash
    pub password_hash: Option<String>,
    pub role: UserRole,
    pub phone_number: Option<String>,

    // serde_json::Value is the Rust equivalent of Mongo's "Mixed" or Object
    pub profile_picture: serde_json::Value,
    pub contact_preferences: serde_json::Value,
    pub preferences: Option<serde_json::Value>,

    pub trust_score: i32,
    pub is_banned: bool,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub location: serde_json::Value,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct NewUser {
    #[validate(length(min = 3, max = 100))]
    pub name: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUser {
    pub name: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub phone_number: Option<String>,
    pub profile_picture: Option<serde_json::Value>,
    pub contact_preferences: Option<serde_json::Value>,
    pub preferences: Option<serde_json::Value>,
    pub trust_score: Option<i32>,
    pub is_banned: Option<bool>,
    pub email_verified: Option<bool>,
    pub phone_verified: Option<bool>,
    pub location: Option<serde_json::Value>,
}
