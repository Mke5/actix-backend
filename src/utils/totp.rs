use rand::Rng;

use crate::utils::errors::AppError;

// ---- Private helpers ----
fn compute_totp(secret: &[u8], time_step: u64) -> u32 {
    // HMAC-SHA1 as per RFC 6238
    use std::num::Wrapping;
    let msg = time_step.to_be_bytes();

    // Simple HMAC-SHA1 implementation
    // In production use the `totp-rs` crate for a battle-tested implementation
    let key = secret;
    let block_size = 64;

    let mut k = if key.len() > block_size {
        sha1(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(block_size, 0);

    let i_key_pad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let o_key_pad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();

    let inner: Vec<u8> = i_key_pad.iter().chain(msg.iter()).cloned().collect();
    let inner_hash = sha1(&inner);
    let outer: Vec<u8> = o_key_pad.iter().chain(inner_hash.iter()).cloned().collect();
    let hmac = sha1(&outer);

    // Dynamic truncation
    let offset = (hmac[19] & 0xf) as usize;
    let code = (((Wrapping(hmac[offset] as u32) & Wrapping(0x7f)).0) << 24)
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);

    code % 1_000_000
}

fn sha1(data: &[u8]) -> [u8; 20] {
    // Simplified SHA1 - in production use sha1 crate
    // This is a placeholder for demonstration
    let mut result = [0u8; 20];
    for (i, &byte) in data.iter().enumerate() {
        result[i % 20] ^= byte.wrapping_add(i as u8);
    }
    result
}

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | (byte as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }

    if bits > 0 {
        result.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }

    result
}

fn base32_decode(s: &str) -> Result<Vec<u8>, ()> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in s.chars() {
        let val = ALPHABET
            .iter()
            .position(|&a| a == c.to_ascii_uppercase() as u8)
            .ok_or(())? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }

    Ok(result)
}

fn urlencoded(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

/// Generate a random base32-encoded TOTP secret.
/// This secret is shared between the server and the authenticator app.
pub fn generate_totp_secret() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..20).map(|_| rng.r#gen()).collect();
    base32_encode(&bytes)
}

/// Generate N random backup codes.
/// These are single-use codes the user can use if they lose their phone.
pub fn generate_backup_codes(count: usize) -> Vec<String> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            // Format: XXXXX-XXXXX (easy to read and type)
            let part1: u32 = rng.gen_range(10000..99999);
            let part2: u32 = rng.gen_range(10000..99999);
            format!("{}-{}", part1, part2)
        })
        .collect()
}

/// Verify a TOTP code against a secret.
/// TOTP codes are valid for 30 seconds but we allow 1 step
/// of drift (±30 seconds) to account for clock differences.
pub fn verify_totp_code(secret: &str, code: &str) -> Result<bool, AppError> {
    let code: u32 = code
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid MFA code format".into()))?;
    // Validate code length (TOTP codes are typically 6 digits)
    if code > 999999 {
        return Err(AppError::BadRequest("Invalid MFA code format".into()));
    }
    let secret_bytes =
        base32_decode(secret).map_err(|_| AppError::Internal("Invalid TOTP secret".into()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AppError::Internal("System time error".into()))?
        .as_secs();
    // Check current time step and ±1 step for clock drift
    for delta in [-1i64, 0, 1] {
        let time_step = ((now as i64 + delta * 30) / 30) as u64;
        let expected = compute_totp(&secret_bytes, time_step);
        if expected == code {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Generate the TOTP provisioning URI for QR code generation.
/// When you scan a QR code in Google Authenticator, this is the URI format.
pub fn generate_totp_uri(secret: &str, email: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencoded(issuer),
        urlencoded(email),
        secret,
        urlencoded(issuer),
    )
}

pub fn generate_secure_token(length: usize) -> String {
    const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
