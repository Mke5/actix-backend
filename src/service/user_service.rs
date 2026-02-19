use std::time::Duration;

use chrono::Utc;
use eyre::Ok;
use eyre::Result;
use eyre::WrapErr;
use sqlx::{Error as SqlxError, PgPool};
use uuid::Uuid;

use crate::config::config::Config;
use crate::models::otp_codes::OtpCode;
use crate::service::email_service::EmailService;
use crate::{
    config::crypto::CryptoService,
    models::user::{NewUser, User},
};

pub struct UserService {
    pub pool: PgPool,
    pub crypto: CryptoService,
    pub platform_name: String,
    pub email_service: EmailService,
}

impl UserService {
    pub fn new(pool: PgPool, crypto: CryptoService, config: &Config) -> Self {
        Self {
            pool,
            crypto,
            platform_name: config.platform_name.clone(),
        }
    }

    pub async fn check_otp_restrictions(&self, email: &str) -> Result<()> {
        let email = email.trim().to_lowercase();
        let record: Option<OtpCode> = sqlx::query_as::<_, OtpCode>(
            r#"
                SELECT *
                FROM otp_codes
                WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .wrap_err("Failed to fetch OTP record")?;

        if let Some(otp) = record {
            let now = Utc::now();
            // Spam Lock (1 hour)
            if let Some(spam_locked_until) = otp.spam_locked_until {
                if spam_locked_until > now {
                    return Err(eyre::eyre!(
                        "Too many OTP requests! Please wait 1 hour before requesting again"
                    ));
                }
            }

            // Cooldown (1 minute)
            if otp.last_request_at > now - Duration::minutes(1) {
                return Err(eyre::eyre!(
                    "Please wait 1 minute before requesting a new OTP!"
                ));
            }

            // Failed attempts lock (30 minutes)
            if otp.attempts >= 3 {
                if otp.last_request_at > now - Duration::minutes(30) {
                    return Err(eyre::eyre!(
                        "Account locked due to multiple failed attempts! Try again after 30 minutes"
                    ));
                }
            }
        }

        Ok(())
    }

    pub async fn verify_otp(&self, email: &str, input_otp: &str) -> Result<()> {
        let email = email.trim().to_lowercase();
        let mut tx = self.pool.begin().await?;
        let record: Option<OtpCode> =
            sqlx::query_as::<Postgres, OtpCode>("SELECT * FROM otp_codes WHERE email = $1")
                .bind(email)
                .fetch_optional(&mut *tx)
                .await
                .wrap_err("Failed to fetch OTP")?;
        let mut otp = match record {
            Some(r) => r,
            None => {
                tx.rollback().await?;
                return Err(eyre!("Invalid or expired OTP!"));
            }
        };
        let now = Utc::now();

        // Expired
        if otp.expires_at < now {
            sqlx::query!("DELETE FROM otp_codes WHERE email = $1", email)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Err(eyre!("Invalid or expired OTP!"));
        };

        // Active lock check (30 min lock using spam_locked_until)
        if let Some(lock_until) = otp.spam_locked_until {
            if lock_until > now {
                tx.rollback().await?;
                return Err(eyre!("Too many failed attempts. Try again later."));
            }
        }

        // Wrong OTP
        let is_valid = self.crypto.verify_password(input_otp, &otp.code)?;
        if !is_valid {
            // Reset attempts if 5 min window passed
            if otp.last_request_at < now - Duration::minutes(5) {
                otp.attempts = 0;
            }

            otp.attempts += 1;
            if otp.attempts >= 3 {
                // Lock for 30 minutes using spam_locked_until
                sqlx::query!(
                    r#"
                        UPDATE otp_codes
                        SET attempts = $1,
                            spam_locked_until = NOW() + INTERVAL '30 minutes'
                        WHERE email = $2
                    "#,
                    new_attempts,
                    email
                )
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Err(eyre!(
                    "Too many failed attempts. Your account is locked for 30 minutes!"
                ));
            }

            sqlx::query!(
                "UPDATE otp_codes SET attempts = $1 WHERE email = $2",
                otp.attempts,
                email
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(eyre!("Invalid OTP!"));
        }

        // Correct OTP → cleanup
        sqlx::query!("DELETE FROM otp_codes WHERE email = $1", email)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn track_otp_request(&self, email: &str) -> Result<()> {
        let email = email.trim().to_lowercase();
        let mut tx = self.pool.begin().await?;
        let record: Option<OtpCode> =
            sqlx::query_as::<_, OtpCode>("SELECT * FROM otp_codes WHERE email = $1")
                .bind(email)
                .fetch_optional(&mut *tx)
                .await?;
        let now = Utc::now();
        if let Some(otp) = record {
            // Spam lock active?
            if let Some(lock_until) = otp.spam_locked_until {
                if lock_until > now {
                    tx.rollback().await?;
                    return Err(eyre!(
                        "Too many requests. Please wait 1 hour before requesting again."
                    ));
                }
            }

            // Reset request window if 1 hour passed
            let new_count = if otp.last_request_at < now - Duration::hours(1) {
                1
            } else {
                otp.request_count + 1
            };

            if new_count >= 3 {
                sqlx::query!(
                    r#"
                        UPDATE otp_codes
                        SET request_count = $1,
                            spam_locked_until = NOW() + INTERVAL '1 hour'
                        WHERE email = $2
                    "#,
                    new_count,
                    email
                )
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Err(eyre!(
                    "Too many requests. Please wait 1 hour before requesting again."
                ));
            }

            sqlx::query!(
                r#"
                    UPDATE otp_codes
                    SET request_count = $1,
                        last_request_at = NOW()
                    WHERE email = $2
                "#,
                new_count,
                email
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn send_otp(&self, name: &str, email: &str) -> Result<()> {
        let email = email.trim().to_lowercase();
        // Check OTP restrictions and track requests
        self.check_otp_restrictions(&email).await?;
        self.track_otp_request(&email).await?;

        // Generate OTP and hash it
        let otp_code = self.crypto.generate_otp_code()?;
        let hashed_otp = self.crypto.hash_password(&otp_code)?;

        let mut tx = self.pool.begin().await?;

        // Insert or Update OTP
        sqlx::query!(
            r#"
                INSERT INTO otp_codes (
                    email,
                    code,
                    attempts,
                    request_count,
                    expires_at,
                    last_request_at
                )
                VALUES ($1, $2, 0, 1, NOW() + INTERVAL '5 minutes', NOW())
                ON CONFLICT (email)
                DO UPDATE SET
                    code = $2,
                    attempts = 0,
                    expires_at = NOW() + INTERVAL '5 minutes',
                    last_request_at = NOW()
                "#,
            email,
            hashed_otp
        )
        .execute(&mut *tx)
        .await?;

        let template_data = serde_json::json!({
            "name": name,
            "otp": otp_code,
            "platformName": self.platform_name
        });

        self.email_service.send_email(
            &email,
            "Verify Your Email",
            "./templates/otp_email.html",
            &template_data,
        );

        tx.commit().await?;

        Ok(())
    }

    pub async fn user_registration(&self, new_user: NewUser) -> Result<User> {
        let hashed_password = self
            .crypto
            .hash_password(&new_user.password)
            .wrap_err("Failed to hash password")?;

        let result = sqlx::query_as::<_, User>(
            r#"
                INSERT INTO users (
                    id,
                    name,
                    email,
                    password_hash,
                    role,
                    trust_score,
                    is_banned,
                    email_verified,
                    phone_verified,
                    profile_picture,
                    contact_preferences,
                    location,
                    created_at,
                    updated_at
                )
                VALUES (
                    $1, $2, $3, $4, 'user', 0, false, false, false,
                    '{}'::jsonb,
                    '{}'::jsonb,
                    '{}'::jsonb,
                    NOW(),
                    NOW()
                )
                RETURNING *
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(&new_user.name)
        .bind(&new_user.email)
        .bind(&hashed_password)
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(err) => {
                if let SqlxError::Database(db_err) = &err {
                    if db_err.constraint() == Some("idx_users_email") {
                        return Err(eyre::eyre!("Email already exists"));
                    }
                }
                Err(err).wrap_err("Failed to insert user")
            }
        }
    }

    pub async fn handle_forgot_password(&self, email: &str) -> Result<()> {
        let email = email.trim().to_lowercase();

        if email.is_empty() {
            return Err(eyre::eyre!("Email is required!"));
        }

        let user: Option<User> =
            sqlx::query_as::<_, User>(r#"SELECT * FROM users WHERE email = $1"#)
                .bind(&email)
                .fetch_optional(&self.pool)
                .await
                .wrap_err("Failed to fetch user")?;
        if user.is_none() {
            return Err(eyre::eyre!("User not found"));
        }
        let user = user.unwrap();
        self.send_otp(&user.name, &user.email)
            .await
            .wrap_err("Failed to send OTP")?;

        Ok(())
    }

    pub async fn verify_forgot_password_otp(&self, email: &str, otp: &str) -> Result<()> {
        let email = email.trim().to_lowercase();
        let otp = otp.trim();
        if email.is_empty() || otp.is_empty() {
            return Err(eyre::eyre!("Email and OTP are required!"));
        }

        self.verify_otp(&email, &otp)
            .await
            .wrap_err("Failed to verify OTP")?;
        Ok(())
    }
}
