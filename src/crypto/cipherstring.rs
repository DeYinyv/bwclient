use anyhow::{anyhow, Context, Result};
use aes::cipher::{BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use block_padding::Pkcs7;
use hmac::Mac as _;
use rand::rngs::OsRng;
use rand::RngCore as _;
use sha2::Sha256;

use super::keys::Keys;

#[derive(Debug, Clone)]
pub struct CipherString {
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    mac: Option<Vec<u8>>,
}

impl CipherString {
    pub fn parse(s: &str) -> Result<Self> {
        let (ty, rest) = s
            .split_once('.')
            .ok_or_else(|| anyhow!("invalid cipherstring: missing type"))?;

        if ty.len() != 1 {
            return Err(anyhow!("unsupported cipherstring type: {ty}"));
        }
        let ty = ty.as_bytes()[0].wrapping_sub(b'0');

        match ty {
            0 | 2 => {
                let parts: Vec<&str> = rest.split('|').collect();

                // According to Bitwarden encryption types:
                // - 0.iv|data
                // - 2.iv|data|mac
                if parts.len() < 2 || parts.len() > 3 {
                    return Err(anyhow!(
                        "invalid type-{ty} cipherstring: expected 2-3 parts, got {}",
                        parts.len()
                    ));
                }

                let iv = STANDARD
                    .decode(parts[0])
                    .context("invalid base64 iv")?;
                let ciphertext = STANDARD
                    .decode(parts[1])
                    .context("invalid base64 ciphertext")?;

                let mac = if parts.len() == 3 {
                    Some(STANDARD.decode(parts[2]).context("invalid base64 mac")?)
                } else {
                    None
                };

                Ok(Self {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            other => Err(anyhow!("unsupported cipherstring type: {other}")),
        }
    }

    pub fn decrypt_to_bytes(&self, keys: &Keys) -> Result<Vec<u8>> {
        if let Some(mac) = &self.mac {
            let mut h = hmac::Hmac::<Sha256>::new_from_slice(keys.mac_key())
                .map_err(|e| anyhow!("hmac init failed: {e:?}"))?;
            h.update(&self.iv);
            h.update(&self.ciphertext);
            h.verify_slice(mac)
                .map_err(|_| anyhow!("invalid mac"))?;
        }

        let decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(keys.enc_key(), &self.iv)
            .map_err(|e| anyhow!("aes-cbc init failed: {e:?}"))?;

        let mut buf = self.ciphertext.clone();
        let pt = decryptor
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow!("decrypt failed: {e:?}"))?;
        Ok(pt.to_vec())
    }

    pub fn decrypt_to_utf8(&self, keys: &Keys) -> Result<String> {
        let bytes = self.decrypt_to_bytes(keys)?;
        String::from_utf8(bytes).context("plaintext was not valid UTF-8")
    }

    pub fn encrypt_bytes(plaintext: &[u8], keys: &Keys) -> Result<String> {
        // Bitwarden commonly uses type 2: iv|data|mac (AES-CBC + HMAC-SHA256 over iv+ciphertext)
        // This produces the EncString format: "2.<b64(iv)>|<b64(ciphertext)>|<b64(mac)>".
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        let encryptor = cbc::Encryptor::<aes::Aes256>::new_from_slices(keys.enc_key(), &iv)
            .map_err(|e| anyhow!("aes-cbc init failed: {e:?}"))?;

        let mut buf = plaintext.to_vec();
        // Ensure there's enough capacity for padding.
        buf.extend_from_slice(&[0u8; 16]);
        let ct = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|e| anyhow!("encrypt failed: {e:?}"))?
            .to_vec();

        let mut h = hmac::Hmac::<Sha256>::new_from_slice(keys.mac_key())
            .map_err(|e| anyhow!("hmac init failed: {e:?}"))?;
        h.update(&iv);
        h.update(&ct);
        let mac = h.finalize().into_bytes();

        let iv_b64 = STANDARD.encode(iv);
        let ct_b64 = STANDARD.encode(ct);
        let mac_b64 = STANDARD.encode(mac);

        Ok(format!("2.{iv_b64}|{ct_b64}|{mac_b64}"))
    }

    pub fn encrypt_utf8(s: &str, keys: &Keys) -> Result<String> {
        Self::encrypt_bytes(s.as_bytes(), keys)
    }
}
