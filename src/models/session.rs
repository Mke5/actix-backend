use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// Session represents an active user session with device and location information.
/// Used for managing multiple login sessions and device tracking.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize, ToSchema)]
pub struct Session {
    /// Unique session identifier
    pub id: Uuid,
    /// The user this session belongs to
    pub user_id: Uuid,
    /// Refresh token associated with this session
    pub refresh_token_hash: String,
    /// User agent string (browser/device info)
    pub user_agent: String,
    /// IP address where the session was created
    pub ip_address: String,
    /// Whether this is an OAuth session
    pub is_oauth: bool,
    /// OAuth provider name (google, github, etc.) if is_oauth is true
    pub oauth_provider: Option<String>,
    /// Whether this session has been manually revoked
    pub is_revoked: bool,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// When the session will automatically expire
    pub expires_at: DateTime<Utc>,
    /// Last time this session was used to make a request
    pub last_used_at: DateTime<Utc>,
}

/// PublicSession is the session data safe to return to clients.
/// It excludes sensitive information like token hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSession {
    pub id: Uuid,
    pub user_agent: String,
    pub ip_address: String,
    pub is_oauth: bool,
    pub oauth_provider: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    /// Whether this is the current session making the request
    pub is_current: bool,
}

/// CreateSessionRequest is used when initiating a new session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub user_agent: String,
    pub ip_address: String,
    pub is_oauth: bool,
    pub oauth_provider: Option<String>,
    pub expiry_days: i64,
}

/// UpdateSessionRequest is used when updating session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSessionRequest {
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_revoked: Option<bool>,
}

/// SessionStats contains aggregated information about user sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub total_active_sessions: i64,
    pub total_revoked_sessions: i64,
    pub oauth_sessions: i64,
    pub device_sessions: i64,
}

impl Session {
    /// Create a new session instance
    pub fn new(
        user_id: Uuid,
        refresh_token_hash: String,
        user_agent: String,
        ip_address: String,
        is_oauth: bool,
        oauth_provider: Option<String>,
        expiry_days: i64,
    ) -> Self {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::days(expiry_days);

        Self {
            id: Uuid::new_v4(),
            user_id,
            refresh_token_hash,
            user_agent,
            ip_address,
            is_oauth,
            oauth_provider,
            is_revoked: false,
            created_at: now,
            expires_at,
            last_used_at: now,
        }
    }

    /// Check if the session is still valid (not revoked and not expired)
    pub fn is_valid(&self) -> bool {
        !self.is_revoked && self.expires_at > Utc::now()
    }

    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Get the time remaining until session expiry
    pub fn time_until_expiry(&self) -> Option<chrono::Duration> {
        let now = Utc::now();
        if self.expires_at > now {
            Some(self.expires_at - now)
        } else {
            None
        }
    }

    /// Parse user agent to extract device information
    pub fn get_device_info(&self) -> DeviceInfo {
        DeviceInfo::from_user_agent(&self.user_agent)
    }

    /// Convert to public session (safe for API responses)
    pub fn to_public(&self, is_current: bool) -> PublicSession {
        PublicSession {
            id: self.id,
            user_agent: self.user_agent.clone(),
            ip_address: self.ip_address.clone(),
            is_oauth: self.is_oauth,
            oauth_provider: self.oauth_provider.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            is_current,
        }
    }
}

/// DeviceInfo contains parsed information about the device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub browser: String,
    pub os: String,
    pub device_type: String,
}

impl DeviceInfo {
    /// Parse user agent string to extract device information
    /// This is a simple implementation; consider using `woothee` crate for production
    pub fn from_user_agent(user_agent: &str) -> Self {
        let user_agent_lower = user_agent.to_lowercase();

        let browser = if user_agent_lower.contains("chrome") {
            "Chrome"
        } else if user_agent_lower.contains("firefox") {
            "Firefox"
        } else if user_agent_lower.contains("safari") {
            "Safari"
        } else if user_agent_lower.contains("edge") {
            "Edge"
        } else {
            "Unknown"
        };

        let os = if user_agent_lower.contains("windows") {
            "Windows"
        } else if user_agent_lower.contains("mac") {
            "macOS"
        } else if user_agent_lower.contains("linux") {
            "Linux"
        } else if user_agent_lower.contains("iphone") {
            "iOS"
        } else if user_agent_lower.contains("android") {
            "Android"
        } else {
            "Unknown"
        };

        let device_type =
            if user_agent_lower.contains("mobile") || user_agent_lower.contains("android") {
                "Mobile"
            } else if user_agent_lower.contains("tablet") || user_agent_lower.contains("ipad") {
                "Tablet"
            } else {
                "Desktop"
            };

        Self {
            browser: browser.to_string(),
            os: os.to_string(),
            device_type: device_type.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            Uuid::new_v4(),
            "hash".to_string(),
            "Mozilla/5.0".to_string(),
            "192.168.1.1".to_string(),
            false,
            None,
            7,
        );

        assert!(!session.is_revoked);
        assert!(session.is_valid());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_device_info_parsing() {
        let device = DeviceInfo::from_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        );

        assert_eq!(device.browser, "Chrome");
        assert_eq!(device.os, "Windows");
        assert_eq!(device.device_type, "Desktop");
    }

    #[test]
    fn test_device_info_mobile() {
        let device = DeviceInfo::from_user_agent(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
        );

        assert_eq!(device.os, "iOS");
        assert_eq!(device.device_type, "Mobile");
    }
}
