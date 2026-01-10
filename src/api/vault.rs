use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::header;
use serde_json::Value;
use url::Url;

use crate::crypto::cipherstring::CipherString;
use crate::crypto::keys::Keys;

fn looks_like_encstring(s: &str) -> bool {
    s.as_bytes()
        .first()
        .copied()
        .is_some_and(|b| b.is_ascii_digit())
        && s.as_bytes().get(1).copied() == Some(b'.')
}

fn decrypt_maybe(s: &str, user_key: &Keys) -> String {
    if looks_like_encstring(s) {
        CipherString::parse(s)
            .and_then(|cs| cs.decrypt_to_utf8(user_key))
            .unwrap_or_else(|_| s.to_string())
    } else {
        s.to_string()
    }
}

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
pub struct VaultClient {
    http: Client,
}

impl Default for VaultClient {
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

fn maybe_dump_sync_json(text: &str) {
    let enabled = std::env::var("BWCLIENT_DUMP_SYNC").ok();
    if enabled.as_deref().is_none_or(|v| v.trim().is_empty() || v == "0") {
        return;
    }

    let base_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let dir = base_dir.join("debuglog");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("clientsync.json");
    let _ = std::fs::write(path, text);
}

#[derive(Debug, Clone)]
pub struct VaultFolder {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultItemType {
    Login,
    SecureNote,
    Card,
    Identity,
    SshKey,
    Unknown(u64),
}

impl VaultItemType {
    pub fn from_wire(v: u64) -> Self {
        match v {
            1 => Self::Login,
            2 => Self::SecureNote,
            3 => Self::Card,
            4 => Self::Identity,
            5 => Self::SshKey,
            other => Self::Unknown(other),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::SecureNote => "Note",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::SshKey => "SSH key",
            Self::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VaultItem {
    pub id: String,
    pub item_type: VaultItemType,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub card: Option<VaultCard>,
    pub identity: Option<VaultIdentity>,
    pub ssh_key: Option<VaultSshKey>,
}

#[derive(Debug, Clone, Default)]
pub struct VaultCard {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VaultIdentity {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,

    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,

    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct VaultSshKey {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VaultItemDraft {
    pub id: Option<String>,
    pub item_type: VaultItemType,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Vec<String>,
    pub notes: Option<String>,
    pub card: Option<VaultCard>,
    pub identity: Option<VaultIdentity>,
    pub ssh_key: Option<VaultSshKey>,
}

#[derive(Debug, Clone)]
pub struct SyncSummary {
    pub cipher_count: usize,
    pub folders: Vec<VaultFolder>,
    pub items: Vec<VaultItem>,
}

impl VaultClient {
    pub fn sync_summary(
        &self,
        api_base: &Url,
        access_token: &str,
        user_key: &Keys,
    ) -> Result<SyncSummary> {
        let url = endpoint(api_base, &["sync"]) ?;

        let resp = self
            .http
            .get(url)
            .bearer_auth(access_token)
            .send()
            .context("sync request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("sync failed: {status} {body}"));
        }

        let text = resp.text().context("failed to read sync response body")?;
        maybe_dump_sync_json(&text);
        let root: Value = serde_json::from_str(&text).context("failed to parse sync response")?;

        let folders_json = root
            .get("folders")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut folders = Vec::with_capacity(folders_json.len());
        for folder in &folders_json {
            let id = folder.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let raw_name = folder
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(no name)");
            let name = decrypt_maybe(raw_name, user_key);
            folders.push(VaultFolder {
                id: id.to_string(),
                name,
            });
        }

        let ciphers = root
            .get("ciphers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut items = Vec::with_capacity(ciphers.len());
        for cipher in &ciphers {
            let id = cipher.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }

            let item_type = VaultItemType::from_wire(
                cipher
                    .get("type")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            );

            let favorite = cipher
                .get("favorite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let folder_id = cipher
                .get("folderId")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let raw_name = cipher
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(no name)");
            let name = decrypt_maybe(raw_name, user_key);

            let notes = cipher
                .get("notes")
                .and_then(|v| v.as_str())
                .map(|s| decrypt_maybe(s, user_key))
                .and_then(|s| if s.trim().is_empty() { None } else { Some(s) });

            let mut username: Option<String> = None;
            let mut password: Option<String> = None;
            let mut totp: Option<String> = None;
            let mut uris: Vec<String> = Vec::new();
            let mut card: Option<VaultCard> = None;
            let mut identity: Option<VaultIdentity> = None;
            let mut ssh_key: Option<VaultSshKey> = None;

            if item_type == VaultItemType::Login && let Some(login) = cipher.get("login") {
                if let Some(raw_username) = login.get("username").and_then(|v| v.as_str()) {
                    let u = decrypt_maybe(raw_username, user_key);
                    if !u.trim().is_empty() {
                        username = Some(u);
                    }
                }
                if let Some(raw_password) = login.get("password").and_then(|v| v.as_str()) {
                    let p = decrypt_maybe(raw_password, user_key);
                    if !p.trim().is_empty() {
                        password = Some(p);
                    }
                }
                if let Some(raw_totp) = login.get("totp").and_then(|v| v.as_str()) {
                    let t = decrypt_maybe(raw_totp, user_key);
                    if !t.trim().is_empty() {
                        totp = Some(t);
                    }
                }
                if let Some(uris_json) = login.get("uris").and_then(|v| v.as_array()) {
                    for u in uris_json {
                        if let Some(raw_uri) = u.get("uri").and_then(|v| v.as_str()) {
                            let s = decrypt_maybe(raw_uri, user_key);
                            if !s.trim().is_empty() {
                                uris.push(s);
                            }
                        }
                    }
                }
            }

            if item_type == VaultItemType::Card && let Some(card_json) = cipher.get("card") {
                    let mut c = VaultCard::default();

                    if let Some(v) = card_json.get("cardholderName").and_then(|v| v.as_str()) {
                        let s = decrypt_maybe(v, user_key);
                        if !s.trim().is_empty() {
                            c.cardholder_name = Some(s);
                        }
                    }
                    if let Some(v) = card_json.get("brand").and_then(|v| v.as_str()) {
                        let s = decrypt_maybe(v, user_key);
                        if !s.trim().is_empty() {
                            c.brand = Some(s);
                        }
                    }
                    if let Some(v) = card_json.get("number").and_then(|v| v.as_str()) {
                        let s = decrypt_maybe(v, user_key);
                        if !s.trim().is_empty() {
                            c.number = Some(s);
                        }
                    }
                    if let Some(v) = card_json.get("expMonth").and_then(|v| v.as_str()) {
                        let s = decrypt_maybe(v, user_key);
                        if !s.trim().is_empty() {
                            c.exp_month = Some(s);
                        }
                    }
                    if let Some(v) = card_json.get("expYear").and_then(|v| v.as_str()) {
                        let s = decrypt_maybe(v, user_key);
                        if !s.trim().is_empty() {
                            c.exp_year = Some(s);
                        }
                    }
                    if let Some(v) = card_json.get("code").and_then(|v| v.as_str()) {
                        let s = decrypt_maybe(v, user_key);
                        if !s.trim().is_empty() {
                            c.code = Some(s);
                        }
                    }

                    if c.cardholder_name.is_some()
                        || c.brand.is_some()
                        || c.number.is_some()
                        || c.exp_month.is_some()
                        || c.exp_year.is_some()
                        || c.code.is_some()
                    {
                        card = Some(c);
                    }
            }

            if item_type == VaultItemType::Identity
                && let Some(identity_json) = cipher.get("identity")
            {
                    let mut ident = VaultIdentity::default();

                    let set_opt = |target: &mut Option<String>, key: &str| {
                        if let Some(v) = identity_json.get(key).and_then(|v| v.as_str()) {
                            let s = decrypt_maybe(v, user_key);
                            if !s.trim().is_empty() {
                                *target = Some(s);
                            }
                        }
                    };

                    set_opt(&mut ident.title, "title");
                    set_opt(&mut ident.first_name, "firstName");
                    set_opt(&mut ident.middle_name, "middleName");
                    set_opt(&mut ident.last_name, "lastName");

                    set_opt(&mut ident.address1, "address1");
                    set_opt(&mut ident.address2, "address2");
                    set_opt(&mut ident.address3, "address3");
                    set_opt(&mut ident.city, "city");
                    set_opt(&mut ident.state, "state");
                    set_opt(&mut ident.postal_code, "postalCode");
                    set_opt(&mut ident.country, "country");

                    set_opt(&mut ident.company, "company");
                    set_opt(&mut ident.email, "email");
                    set_opt(&mut ident.phone, "phone");
                    set_opt(&mut ident.ssn, "ssn");
                    set_opt(&mut ident.username, "username");
                    set_opt(&mut ident.passport_number, "passportNumber");
                    set_opt(&mut ident.license_number, "licenseNumber");

                    if ident.title.is_some()
                        || ident.first_name.is_some()
                        || ident.middle_name.is_some()
                        || ident.last_name.is_some()
                        || ident.address1.is_some()
                        || ident.address2.is_some()
                        || ident.address3.is_some()
                        || ident.city.is_some()
                        || ident.state.is_some()
                        || ident.postal_code.is_some()
                        || ident.country.is_some()
                        || ident.company.is_some()
                        || ident.email.is_some()
                        || ident.phone.is_some()
                        || ident.ssn.is_some()
                        || ident.username.is_some()
                        || ident.passport_number.is_some()
                        || ident.license_number.is_some()
                    {
                        identity = Some(ident);
                    }
            }

            if item_type == VaultItemType::SshKey {
                let ssh_json = cipher
                    .get("sshKey")
                    .or_else(|| cipher.get("ssh_key"))
                    .or_else(|| cipher.get("sshkey"));
                if let Some(ssh_json) = ssh_json {
                    let mut ssh = VaultSshKey::default();

                    let set_opt = |target: &mut Option<String>, keys: &[&str]| {
                        for key in keys {
                            if let Some(v) = ssh_json.get(*key).and_then(|v| v.as_str()) {
                                let s = decrypt_maybe(v, user_key);
                                if !s.trim().is_empty() {
                                    *target = Some(s);
                                    break;
                                }
                            }
                        }
                    };

                    set_opt(&mut ssh.private_key, &["privateKey", "private_key", "private"]);
                    set_opt(&mut ssh.public_key, &["publicKey", "public_key", "public"]);
                    set_opt(
                        &mut ssh.fingerprint,
                        &["keyFingerprint", "key_fingerprint", "fingerprint", "finger_print"],
                    );

                    if ssh.private_key.is_some()
                        || ssh.public_key.is_some()
                        || ssh.fingerprint.is_some()
                    {
                        ssh_key = Some(ssh);
                    }
                }
            }

            items.push(VaultItem {
                id: id.to_string(),
                item_type,
                folder_id,
                favorite,
                name,
                username,
                password,
                totp,
                uris,
                notes,
                card,
                identity,
                ssh_key,
            });
        }

        Ok(SyncSummary {
            cipher_count: ciphers.len(),
            folders,
            items,
        })
    }

    pub fn create_or_update_login_item(
        &self,
        api_base: &Url,
        access_token: &str,
        user_key: &Keys,
        draft: &VaultItemDraft,
    ) -> Result<String> {
        let is_update = draft.id.as_ref().is_some_and(|s| !s.is_empty());
        let url = if is_update {
            endpoint(api_base, &["ciphers", draft.id.as_deref().unwrap_or("")])?
        } else {
            endpoint(api_base, &["ciphers"])?
        };

        let enc_name = CipherString::encrypt_utf8(draft.name.trim(), user_key)?;
        let enc_notes = match draft.notes.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_username = match draft.username.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_password = match draft.password.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_totp = match draft.totp.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };

        let mut uris_json = Vec::new();
        for u in &draft.uris {
            let u = u.trim();
            if u.is_empty() {
                continue;
            }
            let enc_uri = CipherString::encrypt_utf8(u, user_key)?;
            uris_json.push(serde_json::json!({"uri": enc_uri}));
        }

        let mut body = serde_json::json!({
            "type": 1,
            "name": enc_name,
            "favorite": draft.favorite,
            "folderId": draft.folder_id,
            "notes": enc_notes,
            "login": {
                "username": enc_username,
                "password": enc_password,
                "totp": enc_totp,
                "uris": uris_json,
            }
        });
        if is_update && let Some(id) = &draft.id {
            body["id"] = serde_json::Value::String(id.clone());
        }

        let req = if is_update {
            self.http.put(url)
        } else {
            self.http.post(url)
        };

        let resp = req
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .context("cipher write request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("cipher write failed: {status} {body}"));
        }

        let v: Value = resp.json().context("failed to parse cipher write response")?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("cipher").and_then(|c| c.get("id")).and_then(|x| x.as_str()))
            .unwrap_or_default();

        if id.is_empty() {
            // Some servers may not echo; fall back to draft id on update.
            if let Some(existing) = &draft.id {
                return Ok(existing.clone());
            }
            return Err(anyhow!("cipher write response missing id"));
        }

        Ok(id.to_string())
    }

    pub fn create_or_update_note_item(
        &self,
        api_base: &Url,
        access_token: &str,
        user_key: &Keys,
        draft: &VaultItemDraft,
    ) -> Result<String> {
        let is_update = draft.id.as_ref().is_some_and(|s| !s.is_empty());
        let url = if is_update {
            endpoint(api_base, &["ciphers", draft.id.as_deref().unwrap_or("")])?
        } else {
            endpoint(api_base, &["ciphers"])?
        };

        let enc_name = CipherString::encrypt_utf8(draft.name.trim(), user_key)?;
        let enc_notes = match draft.notes.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };

        let mut body = serde_json::json!({
            "type": 2,
            "name": enc_name,
            "favorite": draft.favorite,
            "folderId": draft.folder_id,
            "notes": enc_notes,
            "secureNote": { "type": 0 }
        });
        if is_update && let Some(id) = &draft.id {
            body["id"] = serde_json::Value::String(id.clone());
        }

        let req = if is_update {
            self.http.put(url)
        } else {
            self.http.post(url)
        };

        let resp = req
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .context("cipher write request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("cipher write failed: {status} {body}"));
        }

        let v: Value = resp.json().context("failed to parse cipher write response")?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("cipher").and_then(|c| c.get("id")).and_then(|x| x.as_str()))
            .unwrap_or_default();

        if id.is_empty() {
            if let Some(existing) = &draft.id {
                return Ok(existing.clone());
            }
            return Err(anyhow!("cipher write response missing id"));
        }

        Ok(id.to_string())
    }

    pub fn create_or_update_card_item(
        &self,
        api_base: &Url,
        access_token: &str,
        user_key: &Keys,
        draft: &VaultItemDraft,
    ) -> Result<String> {
        let is_update = draft.id.as_ref().is_some_and(|s| !s.is_empty());
        let url = if is_update {
            endpoint(api_base, &["ciphers", draft.id.as_deref().unwrap_or("")])?
        } else {
            endpoint(api_base, &["ciphers"])?
        };

        let enc_name = CipherString::encrypt_utf8(draft.name.trim(), user_key)?;
        let enc_notes = match draft.notes.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };

        let card = draft.card.clone().unwrap_or_default();

        let enc_cardholder_name = match card.cardholder_name.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_brand = match card.brand.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_number = match card.number.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_exp_month = match card.exp_month.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_exp_year = match card.exp_year.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };
        let enc_code = match card.code.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };

        let mut body = serde_json::json!({
            "type": 3,
            "name": enc_name,
            "favorite": draft.favorite,
            "folderId": draft.folder_id,
            "notes": enc_notes,
            "card": {
                "cardholderName": enc_cardholder_name,
                "brand": enc_brand,
                "number": enc_number,
                "expMonth": enc_exp_month,
                "expYear": enc_exp_year,
                "code": enc_code
            }
        });
        if is_update && let Some(id) = &draft.id {
            body["id"] = serde_json::Value::String(id.clone());
        }

        let req = if is_update {
            self.http.put(url)
        } else {
            self.http.post(url)
        };

        let resp = req
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .context("cipher write request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("cipher write failed: {status} {body}"));
        }

        let v: Value = resp.json().context("failed to parse cipher write response")?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("cipher").and_then(|c| c.get("id")).and_then(|x| x.as_str()))
            .unwrap_or_default();

        if id.is_empty() {
            if let Some(existing) = &draft.id {
                return Ok(existing.clone());
            }
            return Err(anyhow!("cipher write response missing id"));
        }

        Ok(id.to_string())
    }

    pub fn create_or_update_identity_item(
        &self,
        api_base: &Url,
        access_token: &str,
        user_key: &Keys,
        draft: &VaultItemDraft,
    ) -> Result<String> {
        let is_update = draft.id.as_ref().is_some_and(|s| !s.is_empty());
        let url = if is_update {
            endpoint(api_base, &["ciphers", draft.id.as_deref().unwrap_or("")])?
        } else {
            endpoint(api_base, &["ciphers"])?
        };

        let enc_name = CipherString::encrypt_utf8(draft.name.trim(), user_key)?;
        let enc_notes = match draft.notes.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };

        let ident = draft.identity.clone().unwrap_or_default();

        let enc_opt = |s: Option<&str>| -> Result<Option<String>> {
            match s {
                Some(v) if !v.trim().is_empty() => {
                    Ok(Some(CipherString::encrypt_utf8(v, user_key)?))
                }
                _ => Ok(None),
            }
        };

        let mut body = serde_json::json!({
            "type": 4,
            "name": enc_name,
            "favorite": draft.favorite,
            "folderId": draft.folder_id,
            "notes": enc_notes,
            "identity": {
                "title": enc_opt(ident.title.as_deref())?,
                "firstName": enc_opt(ident.first_name.as_deref())?,
                "middleName": enc_opt(ident.middle_name.as_deref())?,
                "lastName": enc_opt(ident.last_name.as_deref())?,
                "address1": enc_opt(ident.address1.as_deref())?,
                "address2": enc_opt(ident.address2.as_deref())?,
                "address3": enc_opt(ident.address3.as_deref())?,
                "city": enc_opt(ident.city.as_deref())?,
                "state": enc_opt(ident.state.as_deref())?,
                "postalCode": enc_opt(ident.postal_code.as_deref())?,
                "country": enc_opt(ident.country.as_deref())?,
                "company": enc_opt(ident.company.as_deref())?,
                "email": enc_opt(ident.email.as_deref())?,
                "phone": enc_opt(ident.phone.as_deref())?,
                "ssn": enc_opt(ident.ssn.as_deref())?,
                "username": enc_opt(ident.username.as_deref())?,
                "passportNumber": enc_opt(ident.passport_number.as_deref())?,
                "licenseNumber": enc_opt(ident.license_number.as_deref())?
            }
        });
        if is_update && let Some(id) = &draft.id {
            body["id"] = serde_json::Value::String(id.clone());
        }

        let req = if is_update {
            self.http.put(url)
        } else {
            self.http.post(url)
        };

        let resp = req
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .context("cipher write request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow::anyhow!("cipher write failed: {status} {body}"));
        }

        let v: Value = resp.json().context("failed to parse cipher write response")?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("cipher").and_then(|c| c.get("id")).and_then(|x| x.as_str()))
            .unwrap_or_default();

        if id.is_empty() {
            if let Some(existing) = &draft.id {
                return Ok(existing.clone());
            }
            return Err(anyhow::anyhow!("cipher write response missing id"));
        }

        Ok(id.to_string())
    }

    pub fn create_or_update_ssh_key_item(
        &self,
        api_base: &Url,
        access_token: &str,
        user_key: &Keys,
        draft: &VaultItemDraft,
    ) -> Result<String> {
        let is_update = draft.id.as_ref().is_some_and(|s| !s.is_empty());
        let url = if is_update {
            endpoint(api_base, &["ciphers", draft.id.as_deref().unwrap_or("")])?
        } else {
            endpoint(api_base, &["ciphers"])?
        };

        let enc_name = CipherString::encrypt_utf8(draft.name.trim(), user_key)?;
        let enc_notes = match draft.notes.as_deref() {
            Some(s) if !s.trim().is_empty() => Some(CipherString::encrypt_utf8(s, user_key)?),
            _ => None,
        };

        let ssh = draft.ssh_key.clone().unwrap_or_default();

        let enc_opt = |s: Option<&str>| -> Result<Option<String>> {
            match s {
                Some(v) if !v.trim().is_empty() => {
                    Ok(Some(CipherString::encrypt_utf8(v, user_key)?))
                }
                _ => Ok(None),
            }
        };

        let mut body = serde_json::json!({
            "type": 5,
            "name": enc_name,
            "favorite": draft.favorite,
            "folderId": draft.folder_id,
            "notes": enc_notes,
            "sshKey": {
                "privateKey": enc_opt(ssh.private_key.as_deref())?,
                "publicKey": enc_opt(ssh.public_key.as_deref())?,
                "keyFingerprint": enc_opt(ssh.fingerprint.as_deref())?
            }
        });
        if is_update && let Some(id) = &draft.id {
            body["id"] = serde_json::Value::String(id.clone());
        }

        let req = if is_update {
            self.http.put(url)
        } else {
            self.http.post(url)
        };

        let resp = req
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .context("cipher write request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow::anyhow!("cipher write failed: {status} {body}"));
        }

        let v: Value = resp.json().context("failed to parse cipher write response")?;
        let id = v
            .get("id")
            .and_then(|x| x.as_str())
            .or_else(|| v.get("cipher").and_then(|c| c.get("id")).and_then(|x| x.as_str()))
            .unwrap_or_default();

        if id.is_empty() {
            if let Some(existing) = &draft.id {
                return Ok(existing.clone());
            }
            return Err(anyhow::anyhow!("cipher write response missing id"));
        }

        Ok(id.to_string())
    }

    pub fn delete_item(
        &self,
        api_base: &Url,
        access_token: &str,
        id: &str,
    ) -> Result<()> {
        let url = endpoint(api_base, &["ciphers", id])?;
        let resp = self
            .http
            .delete(url)
            .bearer_auth(access_token)
            .send()
            .context("cipher delete request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("cipher delete failed: {status} {body}"));
        }

        Ok(())
    }

    /// Trigger sending an email login 2FA code. Mirrors browser behavior for
    /// `/api/two-factor/send-email-login` used by official web client.
    pub fn send_email_login(
        &self,
        api_base: &Url,
        email: &str,
        master_password_hash_b64: &str,
        device_identifier: &str,
        origin: Option<&str>,
    ) -> Result<()> {
        let url = endpoint(api_base, &["two-factor", "send-email-login"]) ?;

        let body = serde_json::json!({
            "email": email,
            "masterPasswordHash": master_password_hash_b64,
            "ssoEmail2FaSessionToken": "",
            "deviceIdentifier": device_identifier,
            "authRequestAccessCode": "",
            "authRequestId": ""
        });

        let mut req = self.http.post(url).json(&body);
        if let Some(o) = origin {
            req = req.header("Origin", o).header(header::REFERER, o);
        }

        let resp = req.send().context("send-email-login request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("send-email-login failed: {status} {body}"));
        }

        Ok(())
    }
}

