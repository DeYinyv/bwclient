use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::header;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use serde_json::Value;
use url::Url;

use super::types::{IdentityTokenError, IdentityTokenResponse, IdentityTokenSuccess, PreloginResponse};

fn endpoint(base: &Url, segments: &[&str]) -> Result<Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow!("base url cannot be a cannot-be-a-base URL: {base}"))?;
        path.pop_if_empty();
        for seg in segments {
            path.push(seg);
        }
    }
    Ok(url)
}

#[derive(Debug, Clone)]
pub struct IdentityClient {
    http: Client,
}

impl Default for IdentityClient {
    fn default() -> Self {
        let mut headers = HeaderMap::new();
        // Some self-hosted servers gate features based on Bitwarden client headers.
        headers.insert(
            "Bitwarden-Client-Name",
            HeaderValue::from_static("desktop"),
        );
        headers.insert(
            "Bitwarden-Client-Version",
            HeaderValue::from_static("2026.1.0"),
        );

        Self {
            http: Client::builder()
                .user_agent("bwclient/0.1")
                .default_headers(headers)
                .build()
                .expect("reqwest client"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct PreloginRequest<'a> {
    email: &'a str,
}

pub struct TokenPasswordGrantParams<'a> {
    pub email: &'a str,
    pub server_password_hash_b64: &'a str,
    pub client_id: &'a str,
    pub device_type: u32,
    pub device_identifier: &'a str,
    pub device_name: &'a str,
    pub new_device_otp: Option<&'a str>,
    pub two_factor_provider: Option<&'a str>,
    pub two_factor_code: Option<&'a str>,
    pub two_factor_remember: Option<bool>,
    pub origin: Option<&'a str>,
}

impl IdentityClient {
    pub fn with_user_agent(ua: &str) -> Self {
        let mut headers = HeaderMap::new();
        // Some self-hosted servers gate features based on Bitwarden client headers.
        headers.insert(
            "Bitwarden-Client-Name",
            HeaderValue::from_static("desktop"),
        );
        headers.insert(
            "Bitwarden-Client-Version",
            HeaderValue::from_static("2026.1.0"),
        );

        Self {
            http: Client::builder()
                .user_agent(ua)
                .default_headers(headers)
                .build()
                .expect("reqwest client"),
        }
    }

    fn maybe_dump_identity(tag: &str, text: &str) {
        let enabled = std::env::var("BWCLIENT_DUMP_IDENTITY").ok();
        if enabled.as_deref().is_none_or(|v| v.trim().is_empty() || v == "0") {
            return;
        }

        let base_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
        let dir = base_dir.join("debuglog");
        let _ = std::fs::create_dir_all(&dir);

        let path = dir.join(format!("identity_{}.json", tag));

        // Try to sanitize token success responses (remove access_token/refresh_token/Key).
        if tag == "token" && let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("access_token");
                obj.remove("refresh_token");
                obj.remove("Key");
                obj.remove("key");
            }
            let _ = std::fs::write(
                path,
                serde_json::to_string_pretty(&v).unwrap_or_else(|_| text.to_string()),
            );
            return;
        }

        let _ = std::fs::write(path, text);
    }

    pub fn prelogin(&self, identity_base: &Url, email: &str) -> Result<PreloginResponse> {
        let url = endpoint(identity_base, &["accounts", "prelogin"]) ?;

        let resp = self
            .http
            .post(url)
            .json(&PreloginRequest { email })
            .send()
            .context("prelogin request failed")?;

        let status = resp.status();
        let text = resp.text().unwrap_or_default();

        // Dump for debugging when enabled.
        Self::maybe_dump_identity("prelogin", &text);

        if !status.is_success() {
            return Err(anyhow!("prelogin failed: {status} {text}"));
        }

        serde_json::from_str(&text).context("failed to parse prelogin response")
    }

    pub fn token_password_grant(
        &self,
        identity_base: &Url,
        params: TokenPasswordGrantParams<'_>,
    ) -> Result<IdentityTokenResponse> {
        let url = endpoint(identity_base, &["connect", "token"]) ?;

        // Bitwarden uses OAuth2 password grant here, with extra device fields.
        // For self-hosted servers we stick to the desktop public client.
        let mut form: Vec<(&str, String)> = vec![
            ("client_id", params.client_id),
            ("grant_type", "password"),
            ("username", params.email),
            ("password", params.server_password_hash_b64),
            ("scope", "api offline_access"),
            ("deviceType", &params.device_type.to_string()),
            ("deviceIdentifier", params.device_identifier),
            ("deviceName", params.device_name),
        ]
        .into_iter()
        .map(|(k, v)| (k, v.to_string()))
        .collect();

        if let Some(otp) = params.new_device_otp {
            let otp = otp.trim();
            if !otp.is_empty() {
                form.push(("newDeviceOtp", otp.to_string()));
            }
        }

        if let Some(provider) = params.two_factor_provider {
            let p = provider.trim();
            if !p.is_empty() {
                form.push(("twoFactorProvider", p.to_string()));
            }
        }

        if let Some(code) = params.two_factor_code {
            let c = code.trim();
            if !c.is_empty() {
                // Some servers expect `twoFactorToken` (browser uses this); include both for compatibility.
                form.push(("twoFactorToken", c.to_string()));
                form.push(("twoFactorCode", c.to_string()));
            }
        }

        if let Some(remember) = params.two_factor_remember {
            form.push(("twoFactorRemember", if remember { "1" } else { "0" }.to_string()));
        }

        let mut req = self
            .http
            .post(url)
            // Standard headers.
            .header(header::ACCEPT, "application/json")
            .header(
                header::CONTENT_TYPE,
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .header("Device-Type", params.device_type.to_string())
            .form(&form);

        if let Some(o) = params.origin {
            req = req.header("Origin", o).header(header::REFERER, o);
        }

        let resp = req.send().context("token request failed")?;

        let status = resp.status();
        let text = resp.text().unwrap_or_default();

        // Dump token responses (sanitized on success) when debug env is set.
        Self::maybe_dump_identity("token", &text);

        if status.is_success() {
            let parsed: IdentityTokenSuccess = serde_json::from_str(&text)
                .with_context(|| format!("failed to parse token success response: {text}"))?;
            return Ok(IdentityTokenResponse::Success(parsed));
        }

        // Error responses are usually JSON, but there are multiple shapes.
        // 1) OAuth error: { Error, ErrorDescription, TwoFactorProviders2, ... }
        // 2) API error envelope: { ErrorModel: { Message: "new device verification required", ... } }
        let mut parsed: IdentityTokenError = serde_json::from_str(&text).unwrap_or_else(|_| {
            let lower = text.to_lowercase();
            // Try extracting ErrorModel.Message if present.
            if let Ok(v) = serde_json::from_str::<Value>(&text)
                && let Some(msg) = v
                    .get("ErrorModel")
                    .and_then(|m| m.get("Message"))
                    .and_then(|m| m.as_str())
            {
                let is_new_device = msg
                    .to_lowercase()
                    .contains("new device verification required");
                return IdentityTokenError {
                    error: Some(if is_new_device {
                        "new_device_verification_required".to_string()
                    } else {
                        "request_failed".to_string()
                    }),
                    error_description: Some(msg.to_string()),
                    two_factor_providers: None,
                    two_factor_providers2: None,
                    device_verification_request: Some(is_new_device),
                };
            }

            // Fallback: keep raw body.
            IdentityTokenError {
                error: Some("request_failed".to_string()),
                error_description: Some(format!("{status} {text}")),
                two_factor_providers: None,
                two_factor_providers2: None,
                device_verification_request: Some(
                    lower.contains("new device verification required")
                        || lower.contains("invalid new device otp"),
                ),
            }
        });

        // Some servers omit/blank the OAuth fields; surface the raw body instead.
        let msg = parsed.message();
        let is_effectively_unknown = msg.trim().is_empty()
            || msg.trim() == ":"
            || msg.starts_with("unknown token error")
            || (parsed.error.is_none() && parsed.error_description.is_none());

        if is_effectively_unknown {
            parsed.error = parsed.error.clone().or(Some("request_failed".to_string()));
            parsed.error_description = Some(format!("{status} {text}"));
        }

        Ok(IdentityTokenResponse::Error(parsed))
    }
}
