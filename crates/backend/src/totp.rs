//! TOTP (Time-based One-Time Password) verification per RFC 6238.
//!
//! Provides generation and verification of 6-digit TOTP codes using
//! HMAC-SHA1 with a configurable time step (default 30 seconds).

use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// Default time step in seconds (RFC 6238 recommends 30).
const DEFAULT_PERIOD: u64 = 30;

/// Number of time steps to check before/after the current one,
/// to accommodate clock skew between client and server.
const SKEW_STEPS: u64 = 1;

/// Generate a TOTP code for the given secret and unix timestamp.
///
/// The secret should be the raw bytes (decoded from base32).
fn generate_code(secret: &[u8], time_step: u64, digits: u32) -> u32 {
    let time_bytes = time_step.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&time_bytes);
    let result = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 Section 5.4)
    let offset = (result[19] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);

    binary % 10u32.pow(digits)
}

/// Verify a TOTP code against a base32-encoded secret.
///
/// Returns `true` if the code matches the current time step or one of the
/// adjacent steps (to tolerate clock skew).
///
/// # Arguments
///
/// * `secret_base32` - The shared secret, base32-encoded (no padding).
/// * `code` - The 6-digit code string submitted by the user.
/// * `period` - Time step in seconds (typically 30).
/// * `digits` - Number of digits in the code (typically 6).
pub fn verify(secret_base32: &str, code: &str, period: u64, digits: u32) -> bool {
    let Ok(expected_code) = code.parse::<u32>() else {
        return false;
    };

    let secret = match data_encoding::BASE32_NOPAD.decode(secret_base32.as_bytes()) {
        Ok(s) => s,
        Err(_) => {
            // Try with padding
            match data_encoding::BASE32.decode(secret_base32.as_bytes()) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
    };

    let period = if period == 0 { DEFAULT_PERIOD } else { period };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs();

    let current_step = now / period;

    // Check the current step and adjacent steps for clock skew tolerance.
    for step in current_step.saturating_sub(SKEW_STEPS)..=current_step + SKEW_STEPS {
        if generate_code(&secret, step, digits) == expected_code {
            return true;
        }
    }

    false
}

/// Generate a random base32-encoded TOTP secret (160 bits / 20 bytes).
pub fn generate_secret(rng: &mut (impl rand_core::RngCore + ?Sized)) -> String {
    let mut key = [0u8; 20];
    rng.fill_bytes(&mut key);
    data_encoding::BASE32_NOPAD.encode(&key)
}

/// Build a `otpauth://` URI for QR code generation.
///
/// The returned URI can be rendered as a QR code for authenticator app
/// scanning.
pub fn build_otpauth_uri(secret_base32: &str, issuer: &str, account_name: &str) -> String {
    // Manual percent-encoding for the label portion
    let label = format!("{}:{}", issuer, account_name);
    let encoded_label: String = label
        .bytes()
        .flat_map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@' => {
                vec![b as char]
            }
            _ => format!("%{b:02X}").chars().collect(),
        })
        .collect();

    format!(
        "otpauth://totp/{encoded_label}?secret={secret_base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_rfc_vector() {
        // RFC 6238 test vector: secret = "12345678901234567890" (ASCII),
        // time = 59 => step = 1, expected TOTP = 287082
        let secret = b"12345678901234567890";
        let code = generate_code(secret, 1, 6);
        assert_eq!(code, 287082);
    }

    #[test]
    fn test_generate_code_step_0() {
        // RFC 6238: time step 0 is not explicitly tested but we verify no panic.
        let secret = b"12345678901234567890";
        let _ = generate_code(secret, 0, 6);
    }

    #[test]
    fn test_generate_secret_length() {
        let mut rng = rand_core::OsRng;
        let secret = generate_secret(&mut rng);
        // 20 bytes = 160 bits, base32 encodes to 32 chars (no padding)
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn test_build_otpauth_uri() {
        let uri = build_otpauth_uri("JBSWY3DPEHPK3PXP", "Pasion", "user@example.com");
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("issuer="));
    }
}
