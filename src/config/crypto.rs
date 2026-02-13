use argon2::password_hash::{PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHash, Version};
use color_eyre::Result;
use rand_core::OsRng;
use std::sync::Arc;
use tracing::instrument;

#[derive(Debug, Clone)]
pub struct CryptoService {
    pub key: Arc<String>,
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
        let code = rand::thread_rng().gen_range(100_000..=999_999);
        Ok(code.to_string())
    }
}
