use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use chrono::{Duration, Utc};
use color_eyre::Result;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CryptoService {
    pub access_key: Arc<String>,
    pub refresh_key: Arc<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: Uuid,     // user id
    pub email: String, // user email
    pub role: String,  // user role
    pub exp: usize,    // expiration time
    pub iat: usize,    // issued at time
}

impl CryptoService {
    fn argon2() -> Result<Argon2<'static>> {
        let params = Params::new(
            32_768, // 32 MB
            3,      // iterations
            1,      // parallelism
            None,
        )
        .map_err(|e| eyre::eyre!("Failed to create Argon2 params: {e}"))?;

        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    #[instrument(skip(self, password))]
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Self::argon2()?;

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| eyre::eyre!("Failed to hash password: {e}"))?
            .to_string();

        Ok(hash)
    }

    #[instrument(skip(self, password, hash))]
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| eyre::eyre!("Invalid password hash format: {e}"))?;

        let argon2 = Self::argon2()?;

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(eyre::eyre!("Password verification failed: {e}")),
        }
    }

    pub fn generate_otp_code(&self) -> Result<String> {
        let mut rng = thread_rng();
        let code = rng.gen_range(100_000..=999_999);
        Ok(code.to_string())
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: String,
    ) -> Result<String> {
        let now = Utc::now();

        let claims = TokenClaims {
            sub: user_id,
            role,
            email: email.to_string(),
            iat: now.timestamp() as usize,
            exp: (now + Duration::minutes(15)).timestamp() as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.access_key.as_bytes()),
        )?;
        Ok(token)
    }

    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: String,
    ) -> Result<String> {
        let now = Utc::now();

        let claims = TokenClaims {
            sub: user_id,
            email: email.to_string(),
            role,
            iat: now.timestamp() as usize,
            exp: (now + Duration::days(7)).timestamp() as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.refresh_key.as_bytes()),
        )?;

        Ok(token)
    }

    pub fn verify_access_token(&self, token: &str) -> Result<TokenClaims> {
        let data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.access_key.as_bytes()),
            &Validation::default(),
        )?;

        Ok(data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<TokenClaims> {
        let data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(self.refresh_key.as_bytes()),
            &Validation::default(),
        )?;

        Ok(data.claims)
    }
}
