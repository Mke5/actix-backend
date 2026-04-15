use lettre::{
    Message, SmtpTransport, Transport, message::header::ContentType,
    transport::smtp::authentication::Credentials,
};
use sqlx::PgPool;

use crate::{config::config::AppConfig, utils::errors::AppError};

/// AppState is the shared data that all request handlers can access.
/// It's like a global variable, but safe and thread-friendly.
pub struct AppState {
    pub db: PgPool,
    pub config: AppConfig,
}

impl AppState {
    pub fn new(db: PgPool, config: AppConfig) -> Self {
        Self { db, config }
    }
}

pub struct EmailService {
    config: crate::config::config::EmailConfig,
}

/// EmailService sends transactional emails (verification, password reset, etc.)
impl EmailService {
    pub fn new(config: crate::config::config::EmailConfig) -> Self {
        Self { config }
    }

    /// Send an email verification code to a new user
    pub async fn send_verification_email(
        &self,
        to_email: &str,
        to_name: &str,
        code: &str,
    ) -> Result<(), AppError> {
        let subject = "Verify your email address";
        let body = format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">  <h1 style="color: #333;">Verify your email</h1>  <p>Hi {},</p>  <p>Thanks for signing up! Please verify your email address using the code below.</p>  <p style="background: #f5f5f5; padding: 20px; border-radius: 4px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #4CAF50;">    {}  </p>  <p style="text-align: center; color: #666;">This code expires in 24 hours.</p>  <p>If you didn't create an account, you can safely ignore this email.</p></body></html>            "#,
            to_name, code
        );

        self.send_email(to_email, subject, &body).await
    }

    /// Send a password reset code
    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        code: &str,
    ) -> Result<(), AppError> {
        let subject = "Reset your password";
        let body = format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">  <h1 style="color: #333;">Reset your password</h1>  <p>We received a request to reset the password for your account.</p>  <p>Please use the code below to reset your password:</p>  <p style="background: #f5f5f5; padding: 20px; border-radius: 4px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #2196F3;">    {}  </p>  <p style="text-align: center; color: #666;">This code expires in 1 hour.</p>  <p><strong>If you didn't request a password reset, please ignore this email. Your password will remain unchanged.</strong></p></body></html>            "#,
            code
        );
        self.send_email(to_email, subject, &body).await
    }

    /// Send a security alert email (e.g., new login from unknown device)
    pub async fn send_security_alert(
        &self,
        to_email: &str,
        alert_type: &str,
        details: &str,
    ) -> Result<(), AppError> {
        let subject = format!("Security alert: {}", alert_type);
        let body = format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">  <h1 style="color: #f44336;">Security Alert</h1>  <p>We detected the following activity on your account:</p>  <p style="background: #f5f5f5; padding: 15px; border-radius: 4px;"><strong>{}</strong></p>  <p>{}</p>  <p>If this was you, no action is needed. If this wasn't you, please change your password immediately.</p></body></html>            "#,
            alert_type, details
        );
        self.send_email(to_email, &subject, &body).await
    }

    async fn send_email(&self, to: &str, subject: &str, html_body: &str) -> Result<(), AppError> {
        let from = format!("{} <{}>", self.config.from_name, self.config.from_address);
        let email = Message::builder()
            .from(
                from.parse()
                    .map_err(|_| AppError::Internal("Invalid from address".into()))?,
            )
            .to(to
                .parse()
                .map_err(|_| AppError::Internal("Invalid to address".into()))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html_body.to_string())
            .map_err(|e| AppError::Internal(format!("Failed to build email: {}", e)))?;
        let creds = Credentials::new(
            self.config.smtp_user.clone(),
            self.config.smtp_password.clone(),
        );
        let mailer = SmtpTransport::relay(&self.config.smtp_host)
            .map_err(|e| AppError::Internal(format!("SMTP error: {}", e)))?
            .credentials(creds)
            .port(self.config.smtp_port)
            .build();
        mailer.send(&email).map_err(|e| {
            tracing::error!("Failed to send email: {:?}", e);
            AppError::Internal(format!("Failed to send email: {}", e))
        })?;

        Ok(())
    }
}
