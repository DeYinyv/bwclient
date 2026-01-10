use serde::Deserialize;
use serde_json::Value;

/// KDF configuration used to derive the master key.
#[derive(Debug, Clone)]
pub enum KdfConfig {
    Pbkdf2Sha256 { iterations: u32 },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreloginResponse {
    #[serde(rename = "Kdf", alias = "kdf")]
    pub kdf: u32,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,

    // Some servers return an explicit salt to use (can differ from the entered email).
    #[serde(rename = "Salt", alias = "salt")]
    pub salt: Option<String>,
}

impl PreloginResponse {
    pub fn to_kdf_config(&self) -> Option<KdfConfig> {
        match self.kdf {
            0 => Some(KdfConfig::Pbkdf2Sha256 {
                iterations: self.kdf_iterations,
            }),
            1 => Some(KdfConfig::Argon2id {
                iterations: self.kdf_iterations,
                memory_mib: self.kdf_memory?,
                parallelism: self.kdf_parallelism?,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct IdentityTokenSuccess {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,

    #[serde(rename = "Key")]
    pub key: Option<String>,

    // When successful, Bitwarden also includes encrypted keys, KDF, etc.
    // We’ll parse those later during full vault unlock.
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityTokenError {
    #[serde(alias = "Error", alias = "error")]
    pub error: Option<String>,
    #[serde(
        alias = "ErrorDescription",
        alias = "errorDescription",
        alias = "error_description"
    )]
    pub error_description: Option<String>,

    // These are present when 2FA is required.
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    pub two_factor_providers: Option<Value>,

    // Newer Bitwarden servers/clients use TwoFactorProviders2 (map provider->data).
    #[serde(rename = "TwoFactorProviders2", alias = "twoFactorProviders2")]
    pub two_factor_providers2: Option<Value>,

    #[serde(rename = "deviceVerificationRequest", alias = "DeviceVerificationRequest")]
    pub device_verification_request: Option<bool>,
}

impl IdentityTokenError {
    pub fn message(&self) -> String {
        let mut base = match (&self.error, &self.error_description) {
            (Some(err), Some(desc)) => format!("{err}: {desc}"),
            (Some(err), None) => err.clone(),
            (None, Some(desc)) => desc.clone(),
            (None, None) => "unknown token error".to_string(),
        };

        // Bitwarden can intentionally respond with the generic invalid_username_or_password for
        // device verification / 2FA flows; surface any hints if the server included them.
        let mut hints: Vec<&'static str> = Vec::new();
        if self.device_verification_request.unwrap_or(false) {
            hints.push("device verification required");
        }
        if self.two_factor_providers.is_some() || self.two_factor_providers2.is_some() {
            hints.push("2FA required");
        }
        if !hints.is_empty() {
            base.push_str(" (");
            base.push_str(&hints.join(", "));
            base.push(')');
        }

        base
    }
}

#[derive(Debug, Clone)]
pub enum IdentityTokenResponse {
    Success(IdentityTokenSuccess),
    Error(IdentityTokenError),
}
