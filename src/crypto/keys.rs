use anyhow::{anyhow, Result};
use base64::Engine as _;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use crate::api::types::KdfConfig;

#[derive(Debug, Clone)]
pub struct Keys {
    bytes: [u8; 64],
}

impl Keys {
    pub fn from_64(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }

    pub fn to_64(&self) -> [u8; 64] {
        self.bytes
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.bytes[0..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.bytes[32..64]
    }
}

#[derive(Debug, Clone)]
pub struct IdentityDerived {
    #[allow(dead_code)]
    pub master_key_32: [u8; 32],
    pub identity_keys_64: Keys,
    pub server_password_hash_b64: String,
}

/// Derive the identity keys (enc+mac) and server auth hash, matching rbw/Bitwarden behavior.
///
/// - PBKDF2: masterKey = PBKDF2-SHA256(masterPassword, salt, iterations, 32)
/// - Argon2id: masterKey = Argon2id(masterPassword, salt, params, 32)
/// - server hash (masterPasswordHash): PBKDF2-SHA256(password=masterKey, salt=masterPassword, 1, 32) then Base64
/// - identity keys: HKDF-SHA256(PRK=masterKey) expand("enc") and expand("mac") to 32 bytes each
pub fn derive_identity(master_password: &str, salt: &str, kdf: &KdfConfig) -> Result<IdentityDerived> {
    // Bitwarden normalizes the salt using trim + lowercase.
    // (Even if the server returns a salt string, this keeps behavior consistent.)
    let salt = salt.trim().to_lowercase();

    let mut master_key_32 = [0u8; 32];

    match kdf {
        KdfConfig::Pbkdf2Sha256 { iterations } => {
            if *iterations == 0 {
                return Err(anyhow!("PBKDF2 iterations cannot be 0"));
            }
            pbkdf2_hmac::<Sha256>(
                master_password.as_bytes(),
                salt.as_bytes(),
                *iterations,
                &mut master_key_32,
            );
        }
        KdfConfig::Argon2id {
            iterations,
            memory_mib,
            parallelism,
        } => {
            if *iterations < 2 || *memory_mib < 16 || *parallelism < 1 {
                return Err(anyhow!(
                    "Argon2id params too low (t={}, m={}MiB, p={})",
                    iterations,
                    memory_mib,
                    parallelism
                ));
            }

            // Bitwarden uses the provided salt directly as the Argon2 salt.
            let salt = salt.as_bytes();
            let memory_kib = memory_mib
                .checked_mul(1024)
                .ok_or_else(|| anyhow!("argon2 memory overflow"))?;

            let params = argon2::Params::new(memory_kib, *iterations, *parallelism, Some(32))
                .map_err(|e| anyhow!("invalid argon2 params: {e:?}"))?;
            let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            argon2
                .hash_password_into(
                    master_password.as_bytes(),
                    salt,
                    &mut master_key_32,
                )
                .map_err(|e| anyhow!("argon2 hash_password_into failed: {e:?}"))?;
        }
    }

    // server auth hash (aka masterPasswordHash)
    // Bitwarden uses PBKDF2-SHA256(password=masterKey, salt=masterPassword, iterations=1, len=32).
    let mut auth_hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_key_32.as_slice(),
        master_password.as_bytes(),
        1,
        &mut auth_hash,
    );
    let server_password_hash_b64 = base64::engine::general_purpose::STANDARD.encode(auth_hash);

    // identity keys via HKDF(PRK=masterKey)
    let hkdf = Hkdf::<Sha256>::from_prk(master_key_32.as_slice())
        .map_err(|_| anyhow!("hkdf from_prk failed"))?;

    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hkdf.expand(b"enc", &mut enc)
        .map_err(|_| anyhow!("hkdf expand enc failed"))?;
    hkdf.expand(b"mac", &mut mac)
        .map_err(|_| anyhow!("hkdf expand mac failed"))?;

    let mut identity = [0u8; 64];
    identity[0..32].copy_from_slice(&enc);
    identity[32..64].copy_from_slice(&mac);

    Ok(IdentityDerived {
        master_key_32,
        identity_keys_64: Keys::from_64(identity),
        server_password_hash_b64,
    })
}
