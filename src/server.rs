use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMode {
    Official,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OfficialRegion {
    /// https://vault.bitwarden.com
    Com,
    /// https://vault.bitwarden.eu
    Eu,
}

/// Server configuration as entered by the user.
///
/// For custom servers, we treat `custom_base_url` as the "server URL" (e.g.
/// `https://bitwarden.example.com`) and derive service URLs as:
/// - identity: `<server>/identity`
/// - api: `<server>/api`
/// - icons: `<server>/icons`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub mode: ServerMode,
    pub official_region: OfficialRegion,
    pub custom_base_url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            mode: ServerMode::Custom,
            official_region: OfficialRegion::Com,
            custom_base_url: "https://localhost/".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerUrls {
    pub identity: Url,
    pub api: Url,
    #[allow(dead_code)]
    pub icons: Url,
}

impl ServerUrls {
    pub fn from_server_base(server_base: &Url) -> Self {
        let mut root = server_base.clone();

        // Normalize: if the user pasted a service URL, try to map it back to a server root.
        // Examples:
        // - https://bw.example.com/api -> https://bw.example.com
        // - https://bw.example.com/identity/ -> https://bw.example.com
        let path = root.path().trim_end_matches('/').to_string();
        if path.ends_with("/api") {
            let new_path = path.trim_end_matches("/api");
            root.set_path(if new_path.is_empty() { "/" } else { new_path });
        } else if path.ends_with("/identity") {
            let new_path = path.trim_end_matches("/identity");
            root.set_path(if new_path.is_empty() { "/" } else { new_path });
        } else if path.ends_with("/icons") {
            let new_path = path.trim_end_matches("/icons");
            root.set_path(if new_path.is_empty() { "/" } else { new_path });
        }

        // Ensure root ends with a single slash before joining.
        root.set_path(&format!("{}/", root.path().trim_end_matches('/')));

        let identity = root.join("identity").expect("join identity");
        let api = root.join("api").expect("join api");
        let icons = root.join("icons").expect("join icons");

        Self { identity, api, icons }
    }
}

impl ServerConfig {
    pub fn urls(&self) -> ServerUrls {
        match self.mode {
            ServerMode::Official => {
                // Cloud environments do NOT derive service URLs from the web vault base.
                // See Bitwarden clients' DefaultEnvironmentService tests.
                let (identity, api, icons) = match self.official_region {
                    OfficialRegion::Com => (
                        "https://identity.bitwarden.com/",
                        "https://api.bitwarden.com/",
                        "https://icons.bitwarden.net/",
                    ),
                    OfficialRegion::Eu => (
                        "https://identity.bitwarden.eu/",
                        "https://api.bitwarden.eu/",
                        "https://icons.bitwarden.eu/",
                    ),
                };

                ServerUrls {
                    identity: Url::parse(identity).expect("valid official identity url"),
                    api: Url::parse(api).expect("valid official api url"),
                    icons: Url::parse(icons).expect("valid official icons url"),
                }
            }
            ServerMode::Custom => {
                let parsed = Url::parse(&self.custom_base_url)
                    .unwrap_or_else(|_| Url::parse("https://localhost/").expect("fallback"));
                ServerUrls::from_server_base(&parsed)
            }
        }
    }
}
