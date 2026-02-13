use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct OtpCode {
    pub email: String,
    pub code: String,
    pub attempts: i32,
    pub request_count: i32,
    pub expires_at: DateTime<Utc>,
    pub last_request_at: DateTime<Utc>,
    pub spam_locked_until: Option<DateTime<Utc>>,
    pub locked_until: Option<DateTime<Utc>>,
}
