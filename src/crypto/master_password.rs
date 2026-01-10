use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::api::types::KdfConfig;

/// Derive the 32-byte master key from the master password and salt (email).
///
/// Matches Bitwarden clients behavior:
/// - PBKDF2-SHA256(password, salt=email, iterations=kdfIterations, dkLen=32)
/// - Argon2id(password, salt=email, params from prelogin, outLen=32)
#[allow(dead_code)]
pub fn derive_master_key(password: &str, salt: &str, kdf: &KdfConfig) -> Result<[u8; 32]> {
    let salt = salt.trim().to_lowercase();
    let password_bytes = password.as_bytes();

    let mut out = [0u8; 32];

    match kdf {
        KdfConfig::Pbkdf2Sha256 { iterations } => {
            if *iterations < 5_000 {
                return Err(anyhow!(
                    "PBKDF2 iterations too low ({}), possible downgrade attack",
                    iterations
                ));
            }
            pbkdf2_hmac::<Sha256>(password_bytes, salt.as_bytes(), *iterations, &mut out);
        }
        KdfConfig::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            if *iterations < 2 || *memory_mib < 16 || *parallelism < 1 {
                return Err(anyhow!(
                    "Argon2id params too low (t={}, m={}MiB, p={}), possible downgrade attack",
                    iterations,
                    memory_mib,
                    parallelism
                ));
            }

            // argon2 crate expects memory in KiB.
            let memory_kib = memory_mib
                .checked_mul(1024)
                .context("argon2 memory overflow")?;

            let params = Params::new(memory_kib, *iterations, *parallelism, Some(out.len()))
                .map_err(|e| anyhow!("invalid argon2 params: {e:?}"))?;

            // Bitwarden uses emailLowerTrim directly as the Argon2 salt.
            let email_salt = salt.as_bytes();

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(password_bytes, email_salt, &mut out)
                .map_err(|e| anyhow!("argon2 hash_password_into failed: {e:?}"))?;
        }
    }

    Ok(out)
}

/// Compute the server master password authentication hash (the value sent as `password` in `/connect/token`).
///
/// Bitwarden clients do:
/// 1) masterKey = deriveKeyFromPassword(password, salt=email, kdf)
/// 2) authHash = PBKDF2-SHA256(password=masterKey_bytes, salt=masterPassword, iterations=1, dkLen=32)
/// 3) Base64(authHash)
#[allow(dead_code)]
pub fn make_server_master_password_hash_b64(
    master_password: &str,
    email: &str,
    kdf: &KdfConfig,
) -> Result<String> {
    let master_key = derive_master_key(master_password, email, kdf)?;

    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(master_key.as_slice(), master_password.as_bytes(), 1, &mut out);

    Ok(STANDARD.encode(out))
}
