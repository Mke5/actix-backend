use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

use crate::utils::errors::AppError;

/// Hash a plain-text password using Argon2id.
///
/// Argon2 is the winner of the Password Hashing Competition (2015).
/// It's designed to be intentionally slow and memory-intensive,
/// which makes brute-force attacks very expensive.
/// We use the "id" variant which protects against both time and memory attacks.
pub fn hash_password(password: &str) -> Result<String, AppError> {
    // SaltString::generate creates a random unique salt for each password.
    // The salt means two identical passwords will have DIFFERENT hashes,
    // making rainbow table attacks useless.
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))
}

/// Check if a plain-text password matches a stored hash.
/// Returns true if they match, false otherwise.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash: {}", e)))?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Check password strength and return any problems found.
/// We validate passwords before storing them to keep accounts safe.
pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long".into());
    }
    if password.len() > 128 {
        return Err("Password must be at most 128 characters long".into());
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("Password must contain at least one uppercase letter".into());
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err("Password must contain at least one lowercase letter".into());
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one number".into());
    }
    if !password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;':\",./<>?".contains(c))
    {
        return Err("Password must contain at least one special character".into());
    }

    // Check for common passwords (in production, use a real list)
    let common_passwords = ["password", "12345678", "qwerty123", "password1"];
    if common_passwords
        .iter()
        .any(|&p| password.to_lowercase().contains(p))
    {
        return Err("Password is too common, please choose a more unique password".into());
    }

    Ok(())
}
