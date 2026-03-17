use base64::{engine::general_purpose::STANDARD, Engine as _};
use iced::widget::{
    button, checkbox, container, pick_list, row, rule, scrollable, text, text_input,
    Space,
};
use iced::{
    Alignment, Element, Font, Length, Size, Subscription, Task, Theme,
};
use serde::{Deserialize, Serialize};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::api::client::{IdentityClient, TokenPasswordGrantParams};
use crate::api::types::IdentityTokenResponse;
use crate::api::vault::{
    SyncSummary, VaultClient, VaultFolder, VaultItem, VaultItemDraft, VaultItemType,
};
use crate::crypto::cipherstring::CipherString;
use crate::crypto::keys::{derive_identity, Keys};
use crate::password_generator::{self, PasswordGeneratorOptions};
use crate::server::{OfficialRegion, ServerConfig, ServerMode};
use crate::totp;

mod view;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ThemeMode {
    Light,
    Dark,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct PersistedSettings {
    theme: ThemeMode,
    password_generator: PasswordGeneratorOptions,
    stay_logged_in: bool,
    login: Option<PersistedLoginInfo>,
}

impl Default for PersistedSettings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::Dark,
            password_generator: PasswordGeneratorOptions::default(),
            stay_logged_in: false,
            login: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PersistedKdfConfig {
    Pbkdf2Sha256 { iterations: u32 },
    Argon2id {
        iterations: u32,
        memory_mib: u32,
        parallelism: u32,
    },
}

impl PersistedKdfConfig {
    fn from_runtime(kdf: &crate::api::types::KdfConfig) -> Self {
        match kdf {
            crate::api::types::KdfConfig::Pbkdf2Sha256 { iterations } => {
                Self::Pbkdf2Sha256 { iterations: *iterations }
            }
            crate::api::types::KdfConfig::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => Self::Argon2id {
                iterations: *iterations,
                memory_mib: *memory_mib,
                parallelism: *parallelism,
            },
        }
    }

    fn to_runtime(&self) -> crate::api::types::KdfConfig {
        match self {
            Self::Pbkdf2Sha256 { iterations } => crate::api::types::KdfConfig::Pbkdf2Sha256 {
                iterations: *iterations,
            },
            Self::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => crate::api::types::KdfConfig::Argon2id {
                iterations: *iterations,
                memory_mib: *memory_mib,
                parallelism: *parallelism,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedLoginInfo {
    server: ServerConfig,
    email: String,
    salt: String,
    kdf: PersistedKdfConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedSession {
    server: ServerConfig,
    access_token: String,
    user_key_b64: String,
}

#[derive(Debug, Clone)]
struct Session {
    access_token: String,
    user_key: Keys,
}

#[derive(Debug, Clone, Default)]
struct LoginForm {
    email: String,
    password: String,
    new_device_otp: String,

    stay_logged_in: bool,

    two_factor_providers: Vec<String>,
    two_factor_provider: Option<String>,
    two_factor_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VaultFolderFilter {
    AllItems,
    Favorites,
    Type(VaultItemType),
    Folder(String),
}

#[derive(Debug, Clone)]
struct VaultUiState {
    search: String,
    selected_item_id: Option<String>,
    selected_folder: VaultFolderFilter,
    user_selected_folder: bool,
    user_selected_item: bool,
    show_password: bool,
    clear_password_clipboard_after_30s: bool,
    password_clipboard_clear_at: Option<Instant>,
}

impl Default for VaultUiState {
    fn default() -> Self {
        Self {
            search: String::new(),
            selected_item_id: None,
            selected_folder: VaultFolderFilter::AllItems,
            user_selected_folder: false,
            user_selected_item: false,
            show_password: false,
            clear_password_clipboard_after_30s: true,
            password_clipboard_clear_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoginFocus {
    CustomBaseUrl,
    Email,
    Password,
    NewDeviceOtp,
    TwoFactorCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppRoute {
    LoggedOut,
    Locked,
    Vault,
}

#[derive(Debug, Clone)]
enum LoginState {
    Idle,
    InProgress { started_at: Instant },
    NeedTwoFactor {
        _providers: Vec<String>,
        message: String,
        device_verification: bool,
    },
    Error(String),
}

#[derive(Debug, Clone)]
enum SyncState {
    Idle,
    InProgress { started_at: Instant },
    Done { cipher_count: usize },
    Error(String),
}

#[derive(Debug, Clone)]
enum ItemOpState {
    Idle,
    InProgress { started_at: Instant },
    Error(String),
}

#[derive(Debug, Clone)]
enum ItemOpResult {
    Upserted { id: String },
    Deleted { id: String },
}

#[derive(Debug, Clone)]
enum ItemOp {
    Upsert(Box<VaultItemDraft>),
    Delete { id: String },
}

#[derive(Debug, Clone)]
struct LoginOk {
    access_token: String,
    user_key: Keys,
    lock_keys: Keys,
    login: PersistedLoginInfo,
}

#[derive(Debug, Clone)]
enum LoginWorkerResult {
    Ok(LoginOk),
    NeedTwoFactor {
        _providers: Vec<String>,
        message: String,
        device_verification: bool,
    },
    Err(String),
}

#[derive(Debug, Clone)]
enum DetailsMode {
    View,
    Edit {
        draft: Box<EditDraft>,
        is_new: bool,
        confirm_delete: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderChoice {
    label: String,
    id: Option<String>,
}

impl std::fmt::Display for FolderChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

#[derive(Debug, Clone)]
struct EditDraft {
    id: Option<String>,
    item_type: VaultItemType,
    folder_id: Option<String>,
    favorite: bool,

    name: String,
    username: String,
    password: String,
    totp: String,
    uris: String,
    notes: String,

    // card
    cardholder_name: String,
    card_brand: String,
    card_number: String,
    card_exp_month: String,
    card_exp_year: String,
    card_code: String,

    // identity
    ident_title: String,
    ident_first: String,
    ident_middle: String,
    ident_last: String,
    ident_company: String,
    ident_email: String,
    ident_phone: String,
    ident_username: String,
    ident_address1: String,
    ident_address2: String,
    ident_address3: String,
    ident_city: String,
    ident_state: String,
    ident_postal: String,
    ident_country: String,
    ident_ssn: String,
    ident_passport: String,
    ident_license: String,

    // ssh key
    ssh_private: String,
    ssh_public: String,
    ssh_fingerprint: String,
}

impl Default for EditDraft {
    fn default() -> Self {
        Self {
            id: None,
            item_type: VaultItemType::Login,
            folder_id: None,
            favorite: false,

            name: String::new(),
            username: String::new(),
            password: String::new(),
            totp: String::new(),
            uris: String::new(),
            notes: String::new(),

            cardholder_name: String::new(),
            card_brand: String::new(),
            card_number: String::new(),
            card_exp_month: String::new(),
            card_exp_year: String::new(),
            card_code: String::new(),

            ident_title: String::new(),
            ident_first: String::new(),
            ident_middle: String::new(),
            ident_last: String::new(),
            ident_company: String::new(),
            ident_email: String::new(),
            ident_phone: String::new(),
            ident_username: String::new(),
            ident_address1: String::new(),
            ident_address2: String::new(),
            ident_address3: String::new(),
            ident_city: String::new(),
            ident_state: String::new(),
            ident_postal: String::new(),
            ident_country: String::new(),
            ident_ssn: String::new(),
            ident_passport: String::new(),
            ident_license: String::new(),

            ssh_private: String::new(),
            ssh_public: String::new(),
            ssh_fingerprint: String::new(),
        }
    }
}

impl EditDraft {
    fn from_item(item: &VaultItem) -> Self {
        let mut d = Self {
            id: Some(item.id.clone()),
            item_type: item.item_type,
            folder_id: item.folder_id.clone(),
            favorite: item.favorite,
            name: item.name.clone(),
            username: item.username.clone().unwrap_or_default(),
            password: item.password.clone().unwrap_or_default(),
            totp: item.totp.clone().unwrap_or_default(),
            uris: item.uris.join("\n"),
            notes: item.notes.clone().unwrap_or_default(),
            ..Default::default()
        };

        if let Some(card) = &item.card {
            d.cardholder_name = card.cardholder_name.clone().unwrap_or_default();
            d.card_brand = card.brand.clone().unwrap_or_default();
            d.card_number = card.number.clone().unwrap_or_default();
            d.card_exp_month = card.exp_month.clone().unwrap_or_default();
            d.card_exp_year = card.exp_year.clone().unwrap_or_default();
            d.card_code = card.code.clone().unwrap_or_default();
        }

        if let Some(ident) = &item.identity {
            d.ident_title = ident.title.clone().unwrap_or_default();
            d.ident_first = ident.first_name.clone().unwrap_or_default();
            d.ident_middle = ident.middle_name.clone().unwrap_or_default();
            d.ident_last = ident.last_name.clone().unwrap_or_default();
            d.ident_company = ident.company.clone().unwrap_or_default();
            d.ident_email = ident.email.clone().unwrap_or_default();
            d.ident_phone = ident.phone.clone().unwrap_or_default();
            d.ident_username = ident.username.clone().unwrap_or_default();
            d.ident_address1 = ident.address1.clone().unwrap_or_default();
            d.ident_address2 = ident.address2.clone().unwrap_or_default();
            d.ident_address3 = ident.address3.clone().unwrap_or_default();
            d.ident_city = ident.city.clone().unwrap_or_default();
            d.ident_state = ident.state.clone().unwrap_or_default();
            d.ident_postal = ident.postal_code.clone().unwrap_or_default();
            d.ident_country = ident.country.clone().unwrap_or_default();
            d.ident_ssn = ident.ssn.clone().unwrap_or_default();
            d.ident_passport = ident.passport_number.clone().unwrap_or_default();
            d.ident_license = ident.license_number.clone().unwrap_or_default();
        }

        if let Some(ssh) = &item.ssh_key {
            d.ssh_private = ssh.private_key.clone().unwrap_or_default();
            d.ssh_public = ssh.public_key.clone().unwrap_or_default();
            d.ssh_fingerprint = ssh.fingerprint.clone().unwrap_or_default();
        }

        d
    }

    fn new_login() -> Self {
        Self {
            item_type: VaultItemType::Login,
            ..Default::default()
        }
    }

    fn to_vault_draft(&self) -> VaultItemDraft {
        use crate::api::vault::{VaultCard, VaultIdentity, VaultSshKey};

        let opt = |s: &str| {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        };

        let uris: Vec<String> = self
            .uris
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect();

        let card = if self.item_type == VaultItemType::Card {
            Some(VaultCard {
                cardholder_name: opt(&self.cardholder_name),
                brand: opt(&self.card_brand),
                number: opt(&self.card_number),
                exp_month: opt(&self.card_exp_month),
                exp_year: opt(&self.card_exp_year),
                code: opt(&self.card_code),
            })
        } else {
            None
        };

        let identity = if self.item_type == VaultItemType::Identity {
            Some(VaultIdentity {
                title: opt(&self.ident_title),
                first_name: opt(&self.ident_first),
                middle_name: opt(&self.ident_middle),
                last_name: opt(&self.ident_last),

                address1: opt(&self.ident_address1),
                address2: opt(&self.ident_address2),
                address3: opt(&self.ident_address3),
                city: opt(&self.ident_city),
                state: opt(&self.ident_state),
                postal_code: opt(&self.ident_postal),
                country: opt(&self.ident_country),

                company: opt(&self.ident_company),
                email: opt(&self.ident_email),
                phone: opt(&self.ident_phone),
                ssn: opt(&self.ident_ssn),
                username: opt(&self.ident_username),
                passport_number: opt(&self.ident_passport),
                license_number: opt(&self.ident_license),
            })
        } else {
            None
        };

        let ssh_key = if self.item_type == VaultItemType::SshKey {
            Some(VaultSshKey {
                private_key: opt(&self.ssh_private),
                public_key: opt(&self.ssh_public),
                fingerprint: opt(&self.ssh_fingerprint),
            })
        } else {
            None
        };

        VaultItemDraft {
            id: self.id.clone(),
            item_type: self.item_type,
            folder_id: self.folder_id.clone(),
            favorite: self.favorite,
            name: self.name.trim().to_string(),
            username: if self.item_type == VaultItemType::Login {
                opt(&self.username)
            } else {
                None
            },
            password: if self.item_type == VaultItemType::Login {
                opt(&self.password)
            } else {
                None
            },
            totp: if self.item_type == VaultItemType::Login {
                opt(&self.totp)
            } else {
                None
            },
            uris: if self.item_type == VaultItemType::Login {
                uris
            } else {
                Vec::new()
            },
            notes: if self.item_type == VaultItemType::SecureNote {
                opt(&self.notes)
            } else {
                // still allow notes in other types if user entered something
                opt(&self.notes)
            },
            card,
            identity,
            ssh_key,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Event(iced::event::Event),
    Tick,

    ThemeToggle,

    ServerModeChanged(ServerMode),
    OfficialRegionChanged(OfficialRegion),
    CustomBaseUrlChanged(String),

    LoginEmailChanged(String),
    LoginPasswordChanged(String),
    LoginNewDeviceOtpChanged(String),
    LoginStayLoggedInToggled(bool),
    LoginContinuePressed,

    TwoFactorProviderChanged(String),
    TwoFactorCodeChanged(String),
    TwoFactorSendCodePressed,
    TwoFactorSubmitPressed,

    VaultSearchChanged(String),
    VaultSelectFolder(VaultFolderFilter),
    VaultSelectItem(String),

    VaultSyncPressed,
    VaultLockPressed,
    VaultLogoutPressed,

    UnlockPasswordChanged(String),
    UnlockPressed,
    LockedLogoutPressed,

    VaultNewItemPressed,
    VaultEditItemPressed,
    VaultCancelEditPressed,
    VaultSaveItemPressed,
    VaultDeleteItemPressed,
    VaultConfirmDeleteToggled(bool),

    EditItemTypeChanged(VaultItemType),
    EditFolderChanged(Option<String>),
    EditFavoriteToggled(bool),

    EditNameChanged(String),
    EditUsernameChanged(String),
    EditPasswordChanged(String),
    EditTotpChanged(String),
    EditUrisChanged(String),
    EditNotesChanged(String),
    EditNotesAction(iced::widget::text_editor::Action),
    EditGeneratePassword,

    EditCardholderChanged(String),
    EditCardBrandChanged(String),
    EditCardNumberChanged(String),
    EditCardExpMonthChanged(String),
    EditCardExpYearChanged(String),
    EditCardCodeChanged(String),

    EditIdentTitleChanged(String),
    EditIdentFirstChanged(String),
    EditIdentMiddleChanged(String),
    EditIdentLastChanged(String),
    EditIdentCompanyChanged(String),
    EditIdentEmailChanged(String),
    EditIdentPhoneChanged(String),
    EditIdentUsernameChanged(String),
    EditIdentAddress1Changed(String),
    EditIdentAddress2Changed(String),
    EditIdentAddress3Changed(String),
    EditIdentCityChanged(String),
    EditIdentStateChanged(String),
    EditIdentPostalChanged(String),
    EditIdentCountryChanged(String),
    EditIdentSsnChanged(String),
    EditIdentPassportChanged(String),
    EditIdentLicenseChanged(String),

    EditSshPrivateChanged(String),
    EditSshPublicChanged(String),
    EditSshFingerprintChanged(String),

    ToggleShowPassword,
    ToggleAutoClearPassword(bool),

    PwGenToggle,
    PwGenRegenerate,
    PwGenCopy,
    PwGenLengthChanged(u32),
    PwGenIncludeUpper(bool),
    PwGenIncludeLower(bool),
    PwGenIncludeDigits(bool),
    PwGenIncludeSpecial(bool),
    PwGenMinNumbersChanged(u32),
    PwGenMinSpecialChanged(u32),

    AboutToggle,

    CopyToClipboard(String),
}

pub struct BwClientIcedApp {
    route: AppRoute,

    server: ServerConfig,
    login: LoginForm,
    login_state: LoginState,
    login_rx: Option<Receiver<LoginWorkerResult>>,

    device_identifier: String,

    persisted_login: Option<PersistedLoginInfo>,
    lock_keys: Option<Keys>,

    unlock_password: String,
    unlock_error: Option<String>,

    session: Option<Session>,

    sync_state: SyncState,
    sync_rx: Option<Receiver<anyhow::Result<SyncSummary>>>,

    item_op_state: ItemOpState,
    item_op_rx: Option<Receiver<anyhow::Result<ItemOpResult>>>,
    pending_select_id: Option<String>,

    vault_ui: VaultUiState,
    vault_folders: Vec<VaultFolder>,
    vault_items: Vec<VaultItem>,
    details_mode: DetailsMode,

    theme_mode: ThemeMode,

    pwgen_open: bool,
    pwgen_options: PasswordGeneratorOptions,
    pwgen_password: String,
    pwgen_error: Option<String>,

    about_open: bool,

    unix_now: u64,

    ui_font: Font,

    login_focus: LoginFocus,
    login_custom_base_url_id: iced::widget::Id,
    login_email_id: iced::widget::Id,
    login_password_id: iced::widget::Id,
    login_new_device_otp_id: iced::widget::Id,
    login_two_factor_code_id: iced::widget::Id,

    unlock_password_id: iced::widget::Id,

    // Edit field IDs for item editing (to support Tab focus)
    edit_name_id: iced::widget::Id,
    edit_username_id: iced::widget::Id,
    edit_password_id: iced::widget::Id,
    edit_totp_id: iced::widget::Id,
    edit_uris_id: iced::widget::Id,

    edit_ident_title_id: iced::widget::Id,
    edit_ident_first_id: iced::widget::Id,
    edit_ident_middle_id: iced::widget::Id,
    edit_ident_last_id: iced::widget::Id,
    edit_ident_company_id: iced::widget::Id,
    edit_ident_username_id: iced::widget::Id,
    edit_ident_email_id: iced::widget::Id,
    edit_ident_phone_id: iced::widget::Id,
    edit_ident_address1_id: iced::widget::Id,
    edit_ident_address2_id: iced::widget::Id,
    edit_ident_address3_id: iced::widget::Id,
    edit_ident_city_id: iced::widget::Id,
    edit_ident_state_id: iced::widget::Id,
    edit_ident_postal_id: iced::widget::Id,
    edit_ident_country_id: iced::widget::Id,
    edit_ident_ssn_id: iced::widget::Id,
    edit_ident_passport_id: iced::widget::Id,
    edit_ident_license_id: iced::widget::Id,

    // Tracks which edit input was last focused (so Tab can continue from there)
    edit_last_focused_id: Option<iced::widget::Id>,

    // Editor content for multi-line notes while editing
    edit_notes_content: Option<iced::widget::text_editor::Content>,
}

impl BwClientIcedApp {
    pub fn run() -> iced::Result {
        iced::application(Self::boot, Self::update, Self::view)
            .title("bwclient")
            .theme(|state: &BwClientIcedApp| match state.theme_mode {
                ThemeMode::Light => Theme::Light,
                ThemeMode::Dark => Theme::Dark,
            })
            .subscription(|state: &BwClientIcedApp| state.subscription())
            .window_size(Size::new(1100.0, 700.0))
            .resizable(true)
            .default_font(Self::default_ui_font())
            .run()
    }

    fn default_ui_font() -> Font {
        #[cfg(target_os = "windows")]
        {
            Font::with_name("Microsoft YaHei")
        }

        #[cfg(not(target_os = "windows"))]
        {
            Font::with_name("Noto Sans CJK SC")
        }
    }

    fn login_focus_chain(&self) -> Vec<(LoginFocus, iced::widget::Id)> {
        let mut chain = Vec::new();

        if self.server.mode == ServerMode::Custom {
            chain.push((LoginFocus::CustomBaseUrl, self.login_custom_base_url_id.clone()));
        }

        chain.push((LoginFocus::Email, self.login_email_id.clone()));
        chain.push((LoginFocus::Password, self.login_password_id.clone()));
        chain.push((LoginFocus::NewDeviceOtp, self.login_new_device_otp_id.clone()));

        if matches!(self.login_state, LoginState::NeedTwoFactor { .. }) {
            chain.push((LoginFocus::TwoFactorCode, self.login_two_factor_code_id.clone()));
        }

        chain
    }

    fn focus_next_login(&mut self, backwards: bool) -> Task<Message> {
        let chain = self.login_focus_chain();
        if chain.is_empty() {
            return Task::none();
        }

        let current_index = chain
            .iter()
            .position(|(f, _)| *f == self.login_focus)
            .unwrap_or(0);

        let next_index = if backwards {
            (current_index + chain.len() - 1) % chain.len()
        } else {
            (current_index + 1) % chain.len()
        };

        let (next_focus, next_id) = chain[next_index].clone();
        self.login_focus = next_focus;
        iced::widget::operation::focus(next_id)
    }

    fn folder_focus_chain(&self) -> Vec<VaultFolderFilter> {
        let mut chain = vec![
            VaultFolderFilter::AllItems,
            VaultFolderFilter::Favorites,
            VaultFolderFilter::Type(VaultItemType::Login),
            VaultFolderFilter::Type(VaultItemType::Card),
            VaultFolderFilter::Type(VaultItemType::Identity),
            VaultFolderFilter::Type(VaultItemType::SecureNote),
            VaultFolderFilter::Type(VaultItemType::SshKey),
        ];
        for f in &self.vault_folders {
            chain.push(VaultFolderFilter::Folder(f.id.clone()));
        }
        chain
    }

    fn focus_next_folder(&mut self, backwards: bool) -> Task<Message> {
        let chain = self.folder_focus_chain();
        if chain.is_empty() {
            return Task::none();
        }
        let current_index = chain
            .iter()
            .position(|c| *c == self.vault_ui.selected_folder)
            .unwrap_or(0);
        let next_index = if backwards {
            (current_index + chain.len() - 1) % chain.len()
        } else {
            (current_index + 1) % chain.len()
        };
        self.vault_ui.selected_folder = chain[next_index].clone();
        self.vault_ui.user_selected_folder = true;
        self.vault_ui.selected_item_id = None;
        self.vault_ui.user_selected_item = false;
        Task::none()
    }

    fn focus_next_item(&mut self, backwards: bool) -> Task<Message> {
        let items = self.visible_items();
        if items.is_empty() {
            return Task::none();
        }
        let current_index = self
            .vault_ui
            .selected_item_id
            .as_deref()
            .and_then(|sid| items.iter().position(|it| it.id == sid))
            .unwrap_or(0);
        let next_index = if backwards {
            (current_index + items.len() - 1) % items.len()
        } else {
            (current_index + 1) % items.len()
        };
        let next_id = items[next_index].id.clone();
        self.vault_ui.selected_item_id = Some(next_id);
        self.vault_ui.user_selected_item = true;
        self.vault_ui.user_selected_folder = false;
        self.vault_ui.show_password = false;
        self.details_mode = DetailsMode::View;
        Task::none()
    }

    fn edit_focus_chain(&self, item_type: VaultItemType) -> Vec<iced::widget::Id> {
        let mut chain = Vec::new();
        match item_type {
            VaultItemType::Login => {
                chain.push(self.edit_username_id.clone());
                chain.push(self.edit_password_id.clone());
                chain.push(self.edit_totp_id.clone());
                chain.push(self.edit_uris_id.clone());
                chain.push(self.edit_name_id.clone());
            }
            VaultItemType::SecureNote => {
                chain.push(self.edit_name_id.clone());
                // notes use TextEditor; skip
            }
            VaultItemType::Card => {
                chain.push(self.edit_name_id.clone());
                // card fields not added for now
            }
            VaultItemType::Identity => {
                chain.push(self.edit_ident_title_id.clone());
                chain.push(self.edit_ident_first_id.clone());
                chain.push(self.edit_ident_middle_id.clone());
                chain.push(self.edit_ident_last_id.clone());
                chain.push(self.edit_ident_company_id.clone());
                chain.push(self.edit_ident_username_id.clone());
                chain.push(self.edit_ident_email_id.clone());
                chain.push(self.edit_ident_phone_id.clone());
                chain.push(self.edit_ident_address1_id.clone());
                chain.push(self.edit_ident_address2_id.clone());
                chain.push(self.edit_ident_address3_id.clone());
                chain.push(self.edit_ident_city_id.clone());
                chain.push(self.edit_ident_state_id.clone());
                chain.push(self.edit_ident_country_id.clone());
                chain.push(self.edit_ident_postal_id.clone());
                chain.push(self.edit_ident_ssn_id.clone());
                chain.push(self.edit_ident_passport_id.clone());
                chain.push(self.edit_ident_license_id.clone());
            }
            VaultItemType::SshKey => {
                chain.push(self.edit_name_id.clone());
            }
            VaultItemType::Unknown(_) => {
                chain.push(self.edit_name_id.clone());
            }
        }
        chain
    }

    fn focus_next_edit(&mut self, backwards: bool, item_type: VaultItemType) -> Task<Message> {
        let chain = self.edit_focus_chain(item_type);
        if chain.is_empty() {
            return Task::none();
        }
        let current_index = self
            .edit_last_focused_id
            .as_ref()
            .and_then(|id| chain.iter().position(|c| c == id))
            .unwrap_or(0);
        let next_index = if backwards {
            (current_index + chain.len() - 1) % chain.len()
        } else {
            (current_index + 1) % chain.len()
        };
        let next_id = chain[next_index].clone();
        self.edit_last_focused_id = Some(next_id.clone());
        iced::widget::operation::focus(next_id)
    }

    fn exe_dir() -> Option<PathBuf> {
        let exe = std::env::current_exe().ok()?;
        exe.parent().map(|p| p.to_path_buf())
    }

    fn write_private_file(path: &std::path::Path, content: &str) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(content.as_bytes())?;
            f.flush()?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            std::fs::write(path, content)
        }
    }

    fn session_path() -> PathBuf {
        if let Some(dir) = Self::exe_dir() {
            return dir.join("session.json");
        }
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("session.json")
    }

    fn settings_path() -> PathBuf {
        if let Some(dir) = Self::exe_dir() {
            return dir.join("settings.json");
        }
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("settings.json")
    }

    fn data_path() -> PathBuf {
        if let Some(dir) = Self::exe_dir() {
            return dir.join("data.json");
        }
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data.json")
    }

    fn load_settings() -> PersistedSettings {
        let path = Self::settings_path();
        let Ok(s) = std::fs::read_to_string(path) else {
            return PersistedSettings::default();
        };
        serde_json::from_str(&s).unwrap_or_default()
    }

    fn save_settings(&self) {
        let path = Self::settings_path();
        let settings = PersistedSettings {
            theme: self.theme_mode,
            password_generator: self.pwgen_options.clone(),
            stay_logged_in: self.login.stay_logged_in,
            login: self.persisted_login.clone(),
        };
        let Ok(json) = serde_json::to_string_pretty(&settings) else {
            return;
        };
        let _ = Self::write_private_file(&path, &json);
    }

    fn load_persisted_data_encrypted() -> Option<String> {
        let primary = Self::data_path();
        if let Ok(s) = std::fs::read_to_string(&primary)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
            && let Some(enc) = v.get("enc").and_then(|e| e.as_str())
        {
            return Some(enc.to_string());
        }

        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data.json");
        if fallback != primary
            && let Ok(s) = std::fs::read_to_string(&fallback)
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
            && let Some(enc) = v.get("enc").and_then(|e| e.as_str())
        {
            return Some(enc.to_string());
        }

        None
    }

    fn save_persisted_data(&self, session: &Session) {
        let Some(lock_keys) = &self.lock_keys else {
            return;
        };

        #[derive(Serialize, Deserialize)]
        struct PersistedData {
            server: ServerConfig,
            access_token: String,
            user_key_b64: String,
        }

        let user_key_b64 = STANDARD.encode(session.user_key.to_64());
        let data = PersistedData {
            server: self.server.clone(),
            access_token: session.access_token.clone(),
            user_key_b64,
        };

        let Ok(plaintext) = serde_json::to_vec(&data) else {
            return;
        };
        let Ok(enc) = CipherString::encrypt_bytes(&plaintext, lock_keys) else {
            return;
        };

        let Ok(json) = serde_json::to_string_pretty(&serde_json::json!({"enc": enc})) else {
            return;
        };

        let path = Self::data_path();
        if Self::write_private_file(&path, &json).is_ok() {
            return;
        }
        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data.json");
        if fallback != path {
            let _ = Self::write_private_file(&fallback, &json);
        }
    }

    fn delete_persisted_data_file() {
        let path = Self::data_path();
        let _ = std::fs::remove_file(&path);

        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data.json");
        if fallback != path {
            let _ = std::fs::remove_file(fallback);
        }
    }

    fn try_unlock(&mut self) {
        self.unlock_error = None;

        let Some(login) = &self.persisted_login else {
            self.unlock_error = Some("missing login info in settings".to_string());
            return;
        };
        let Some(enc) = Self::load_persisted_data_encrypted() else {
            self.unlock_error = Some("missing data.json".to_string());
            return;
        };

        let runtime_kdf = login.kdf.to_runtime();
        let derived = match derive_identity(&self.unlock_password, &login.salt, &runtime_kdf) {
            Ok(d) => d,
            Err(e) => {
                self.unlock_error = Some(format!("failed to derive key: {e:#}"));
                return;
            }
        };
        let lock_keys = derived.identity_keys_64;

        let plaintext = match CipherString::parse(&enc).and_then(|cs| cs.decrypt_to_bytes(&lock_keys)) {
            Ok(p) => p,
            Err(_) => {
                self.unlock_error = Some("invalid password or corrupted data".to_string());
                return;
            }
        };

        #[derive(Serialize, Deserialize)]
        struct PersistedData {
            server: ServerConfig,
            access_token: String,
            user_key_b64: String,
        }

        let data: PersistedData = match serde_json::from_slice(&plaintext) {
            Ok(v) => v,
            Err(e) => {
                self.unlock_error = Some(format!("failed to parse data.json payload: {e:#}"));
                return;
            }
        };

        let user_key_bytes = match STANDARD.decode(data.user_key_b64) {
            Ok(v) => v,
            Err(_) => {
                self.unlock_error = Some("invalid user key in data.json".to_string());
                return;
            }
        };

        let user_key_64: [u8; 64] = match user_key_bytes.as_slice().try_into() {
            Ok(v) => v,
            Err(_) => {
                self.unlock_error = Some("invalid user key in data.json".to_string());
                return;
            }
        };

        self.server = data.server;
        self.session = Some(Session {
            access_token: data.access_token,
            user_key: Keys::from_64(user_key_64),
        });
        self.lock_keys = Some(lock_keys);

        self.unlock_password.clear();
        self.vault_ui.selected_item_id = None;
        self.vault_ui.selected_folder = VaultFolderFilter::AllItems;
        self.vault_ui.user_selected_folder = false;
        self.vault_ui.user_selected_item = false;
        self.route = AppRoute::Vault;
    }

    fn load_persisted_session() -> Option<PersistedSession> {
        let primary = Self::session_path();
        if let Ok(s) = std::fs::read_to_string(&primary)
            && let Ok(persisted) = serde_json::from_str::<PersistedSession>(&s)
        {
            return Some(persisted);
        }

        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("session.json");
        if fallback != primary
            && let Ok(s) = std::fs::read_to_string(&fallback)
            && let Ok(persisted) = serde_json::from_str::<PersistedSession>(&s)
        {
            return Some(persisted);
        }

        None
    }

    fn save_persisted_session(&self, session: &Session) {
        let path = Self::session_path();

        let user_key_b64 = STANDARD.encode(session.user_key.to_64());
        let persisted = PersistedSession {
            server: self.server.clone(),
            access_token: session.access_token.clone(),
            user_key_b64,
        };
        let Ok(json) = serde_json::to_string_pretty(&persisted) else {
            return;
        };

        if Self::write_private_file(&path, &json).is_ok() {
            return;
        }
        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("session.json");
        if fallback != path {
            let _ = Self::write_private_file(&fallback, &json);
        }
    }

    fn delete_persisted_session_file() {
        let path = Self::session_path();
        let _ = std::fs::remove_file(&path);

        let fallback = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("session.json");
        if fallback != path {
            let _ = std::fs::remove_file(fallback);
        }
    }

    fn device_id_path() -> PathBuf {
        if cfg!(target_os = "windows") {
            if let Some(appdata) = std::env::var_os("APPDATA") {
                return PathBuf::from(appdata).join("bwclient").join("device_id.txt");
            }
        } else {
            if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
                return PathBuf::from(xdg).join("bwclient").join("device_id.txt");
            }
            if let Some(home) = std::env::var_os("HOME") {
                return PathBuf::from(home)
                    .join(".config")
                    .join("bwclient")
                    .join("device_id.txt");
            }
        }

        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("bwclient_device_id.txt")
    }

    fn load_or_create_device_identifier() -> String {
        let path = Self::device_id_path();

        if let Ok(existing) = std::fs::read_to_string(&path) {
            let s = existing.trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }

        let created = Uuid::new_v4().to_string();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&path, format!("{created}\n"));
        created
    }

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn poll_login(&mut self) {
        let Some(rx) = &self.login_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(result) => {
                self.login_rx = None;
                match result {
                    LoginWorkerResult::Ok(ok) => {
                        self.login_state = LoginState::Idle;

                        self.server = ok.login.server.clone();
                        self.persisted_login = Some(ok.login);
                        self.lock_keys = Some(ok.lock_keys);
                        self.save_settings();

                        self.session = Some(Session {
                            access_token: ok.access_token,
                            user_key: ok.user_key,
                        });

                        self.route = AppRoute::Vault;

                        if let Some(session) = &self.session {
                            if self.login.stay_logged_in {
                                self.save_persisted_session(session);
                                Self::delete_persisted_data_file();
                            } else {
                                Self::delete_persisted_session_file();
                                self.save_persisted_data(session);
                            }
                        }

                        self.vault_ui.selected_item_id = None;
                        self.vault_ui.selected_folder = VaultFolderFilter::AllItems;
                        self.vault_ui.user_selected_folder = false;
                        self.vault_ui.user_selected_item = false;

                        self.login.two_factor_providers.clear();
                        self.login.two_factor_provider = None;
                        self.login.two_factor_code.clear();
                        self.login.password.clear();
                        self.login.new_device_otp.clear();
                    }
                    LoginWorkerResult::NeedTwoFactor {
                        _providers: providers,
                        message,
                        device_verification,
                    } => {
                        self.login.two_factor_providers = providers.clone();
                        self.login.two_factor_provider =
                            self.login.two_factor_providers.first().cloned();
                        self.login.two_factor_code.clear();
                        self.login_state = LoginState::NeedTwoFactor {
                            _providers: providers,
                            message,
                            device_verification,
                        };
                    }
                    LoginWorkerResult::Err(err) => {
                        self.login_state = LoginState::Error(err);
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.login_rx = None;
                self.login_state = LoginState::Error("login worker disconnected".to_string());
            }
        }
    }

    fn ensure_sync_started(&mut self) {
        if self.session.is_none() {
            return;
        }
        if self.sync_rx.is_some() {
            return;
        }
        if !matches!(self.sync_state, SyncState::Idle) {
            return;
        }

        let session = self.session.clone().expect("session");
        let server = self.server.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        self.sync_state = SyncState::InProgress {
            started_at: Instant::now(),
        };
        self.sync_rx = Some(rx);

        thread::spawn(move || {
            let result: anyhow::Result<SyncSummary> = match catch_unwind(AssertUnwindSafe(|| {
                let urls = server.urls();
                let vault = VaultClient::default();
                vault.sync_summary(&urls.api, &session.access_token, &session.user_key)
            })) {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("sync worker panicked")),
            };

            let _ = tx.send(result);
        });
    }

    fn poll_sync(&mut self) {
        let Some(rx) = &self.sync_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(result) => {
                self.sync_rx = None;
                match result {
                    Ok(summary) => {
                        self.vault_folders = summary.folders;
                        self.vault_items = summary.items;
                        self.sync_state = SyncState::Done {
                            cipher_count: summary.cipher_count,
                        };

                        if let Some(id) = self.pending_select_id.take() {
                            self.vault_ui.selected_item_id = Some(id);
                            self.vault_ui.user_selected_item = true;
                        }
                    }
                    Err(err) => {
                        self.sync_state = SyncState::Error(format!("{err:#}"));
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.sync_rx = None;
                self.sync_state = SyncState::Error("sync worker disconnected".to_string());
            }
        }
    }

    fn poll_item_op(&mut self) {
        let Some(rx) = &self.item_op_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(result) => {
                self.item_op_rx = None;
                self.item_op_state = ItemOpState::Idle;
                match result {
                    Ok(ItemOpResult::Upserted { id }) => {
                        self.pending_select_id = Some(id);
                        self.details_mode = DetailsMode::View;
                        self.vault_ui.show_password = false;
                        self.sync_state = SyncState::Idle;
                        self.sync_rx = None;
                        self.edit_notes_content = None;
                    }
                    Ok(ItemOpResult::Deleted { id }) => {
                        if self.vault_ui.selected_item_id.as_deref() == Some(id.as_str()) {
                            self.vault_ui.selected_item_id = None;
                        }
                        self.details_mode = DetailsMode::View;
                        self.vault_ui.show_password = false;
                        self.sync_state = SyncState::Idle;
                        self.sync_rx = None;
                    }
                    Err(err) => {
                        self.item_op_state = ItemOpState::Error(format!("{err:#}"));
                    }
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.item_op_rx = None;
                self.item_op_state = ItemOpState::Error("item worker disconnected".to_string());
            }
        }
    }

    fn start_item_op(&mut self, op: ItemOp) {
        if self.session.is_none() {
            self.item_op_state = ItemOpState::Error("not logged in".to_string());
            return;
        }
        if self.item_op_rx.is_some() {
            return;
        }

        let session = self.session.clone().expect("session");
        let server = self.server.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.item_op_state = ItemOpState::InProgress {
            started_at: Instant::now(),
        };
        self.item_op_rx = Some(rx);

        thread::spawn(move || {
            let result: anyhow::Result<ItemOpResult> = match catch_unwind(AssertUnwindSafe(|| {
                (|| {
                    let urls = server.urls();
                    let vault = VaultClient::default();
                    match op {
                        ItemOp::Upsert(draft) => {
                            let id = match draft.item_type {
                                VaultItemType::Login => vault.create_or_update_login_item(
                                    &urls.api,
                                    &session.access_token,
                                    &session.user_key,
                                    &draft,
                                )?,
                                VaultItemType::SecureNote => vault.create_or_update_note_item(
                                    &urls.api,
                                    &session.access_token,
                                    &session.user_key,
                                    &draft,
                                )?,
                                VaultItemType::Card => vault.create_or_update_card_item(
                                    &urls.api,
                                    &session.access_token,
                                    &session.user_key,
                                    &draft,
                                )?,
                                VaultItemType::Identity => vault.create_or_update_identity_item(
                                    &urls.api,
                                    &session.access_token,
                                    &session.user_key,
                                    &draft,
                                )?,
                                VaultItemType::SshKey => vault.create_or_update_ssh_key_item(
                                    &urls.api,
                                    &session.access_token,
                                    &session.user_key,
                                    &draft,
                                )?,
                                _ => {
                                    return Err(anyhow::anyhow!(
                                        "unsupported item type: {}",
                                        draft.item_type.label()
                                    ));
                                }
                            };
                            Ok(ItemOpResult::Upserted { id })
                        }
                        ItemOp::Delete { id } => {
                            vault.delete_item(&urls.api, &session.access_token, &id)?;
                            Ok(ItemOpResult::Deleted { id })
                        }
                    }
                })()
            })) {
                Ok(r) => r,
                Err(_) => Err(anyhow::anyhow!("item worker panicked")),
            };

            let _ = tx.send(result);
        });
    }

    fn start_login_with_2fa(
        &mut self,
        tx: Sender<LoginWorkerResult>,
        two_factor_remember_flag: bool,
    ) {
        let email_login = self.login.email.trim().to_string();
        let email_kdf = email_login.to_lowercase();
        let password = self.login.password.clone();
        let new_device_otp = self.login.new_device_otp.trim().to_string();
        let two_factor_provider = self.login.two_factor_provider.clone();
        let two_factor_code = self.login.two_factor_code.trim().to_string();
        let server = self.server.clone();

        let device_identifier = self.device_identifier.clone();

        let (client_id, device_type, device_name) = match self.server.mode {
            ServerMode::Official => ("web".to_string(), 9u32, "chrome".to_string()),
            ServerMode::Custom => {
                let dt = if cfg!(target_os = "windows") {
                    6u32
                } else if cfg!(target_os = "macos") {
                    7u32
                } else {
                    8u32
                };
                ("desktop".to_string(), dt, "bwclient".to_string())
            }
        };

        let remember_flag = two_factor_remember_flag;

        thread::spawn(move || {
            let result: LoginWorkerResult = match catch_unwind(AssertUnwindSafe(|| {
                (|| -> anyhow::Result<LoginWorkerResult> {
                    let urls = server.urls();

                    let origin = if server.mode == ServerMode::Official {
                        Some(format!(
                            "{}://{}",
                            urls.identity.scheme(),
                            urls.identity.host_str().unwrap_or("")
                        ))
                    } else {
                        None
                    };

                    let identity = if server.mode == ServerMode::Official {
                        IdentityClient::with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36")
                    } else {
                        IdentityClient::default()
                    };

                    let prelogin = identity.prelogin(&urls.identity, &email_login)?;
                    let base_kdf = prelogin
                        .to_kdf_config()
                        .ok_or_else(|| anyhow::anyhow!("unsupported KDF type: {}", prelogin.kdf))?;

                    let salt = prelogin.salt.clone().unwrap_or_else(|| email_kdf.clone());

                    let derived = derive_identity(&password, &salt, &base_kdf)?;
                    let server_hash = derived.server_password_hash_b64.clone();

                    let token = identity.token_password_grant(
                        &urls.identity,
                        TokenPasswordGrantParams {
                            email: &email_login,
                            server_password_hash_b64: &server_hash,
                            client_id: &client_id,
                            device_type,
                            device_identifier: &device_identifier,
                            device_name: &device_name,
                            new_device_otp: if new_device_otp.is_empty() {
                                None
                            } else {
                                Some(new_device_otp.as_str())
                            },
                            two_factor_provider: two_factor_provider.as_deref(),
                            two_factor_code: if two_factor_code.is_empty() {
                                None
                            } else {
                                Some(two_factor_code.as_str())
                            },
                            two_factor_remember: Some(remember_flag),
                            origin: origin.as_deref(),
                        },
                    )?;

                    match token {
                        IdentityTokenResponse::Success(ok) => {
                            let protected_key = ok
                                .key
                                .clone()
                                .ok_or_else(|| anyhow::anyhow!("token response missing Key"))?;

                            let cs = CipherString::parse(&protected_key)?;
                            let user_key_bytes = cs.decrypt_to_bytes(&derived.identity_keys_64)?;
                            let user_key_64: [u8; 64] = user_key_bytes
                                .as_slice()
                                .try_into()
                                .map_err(|_| {
                                    anyhow::anyhow!(
                                        "decrypted user key had unexpected length {}",
                                        user_key_bytes.len()
                                    )
                                })?;

                            Ok(LoginWorkerResult::Ok(LoginOk {
                                access_token: ok.access_token,
                                user_key: Keys::from_64(user_key_64),
                                lock_keys: derived.identity_keys_64,
                                login: PersistedLoginInfo {
                                    server,
                                    email: email_login,
                                    salt,
                                    kdf: PersistedKdfConfig::from_runtime(&base_kdf),
                                },
                            }))
                        }
                        IdentityTokenResponse::Error(err) => {
                            let mut providers: Vec<String> = Vec::new();

                            if let Some(v2) = &err.two_factor_providers2
                                && let Some(obj) = v2.as_object()
                            {
                                for (k, _v) in obj {
                                    providers.push(k.clone());
                                }
                            }

                            if providers.is_empty()
                                && let Some(v1) = &err.two_factor_providers
                                && let Some(arr) = v1.as_array()
                            {
                                for it in arr {
                                    if let Some(s) = it.as_str() {
                                        providers.push(s.to_string());
                                    } else if let Some(obj) = it.as_object()
                                        && let Some(name) = obj
                                            .get("provider")
                                            .and_then(|x| x.as_str())
                                    {
                                        providers.push(name.to_string());
                                    }
                                }
                            }

                            if !providers.is_empty() {
                                return Ok(LoginWorkerResult::NeedTwoFactor {
                                    _providers: providers,
                                    message: err.message(),
                                    device_verification: err.device_verification_request
                                        .unwrap_or(false),
                                });
                            }

                            Ok(LoginWorkerResult::Err(err.message()))
                        }
                    }
                })()
            })) {
                Ok(r) => match r {
                    Ok(v) => v,
                    Err(e) => LoginWorkerResult::Err(format!("login worker error: {e:#}")),
                },
                Err(_) => LoginWorkerResult::Err("login worker panicked".to_string()),
            };

            let _ = tx.send(result);
        });
    }

    fn start_send_email_2fa(&mut self, tx: Sender<LoginWorkerResult>) {
        let email_login = self.login.email.trim().to_string();
        let email_kdf = email_login.to_lowercase();
        let password = self.login.password.clone();
        let server = self.server.clone();
        let device_identifier = self.device_identifier.clone();

        thread::spawn(move || {
            let result: LoginWorkerResult = match catch_unwind(AssertUnwindSafe(|| {
                (|| -> anyhow::Result<LoginWorkerResult> {
                    let urls = server.urls();

                    let origin = if server.mode == ServerMode::Official {
                        Some(format!(
                            "{}://{}",
                            urls.identity.scheme(),
                            urls.identity.host_str().unwrap_or("")
                        ))
                    } else {
                        None
                    };

                    let identity = if server.mode == ServerMode::Official {
                        IdentityClient::with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36")
                    } else {
                        IdentityClient::default()
                    };

                    let prelogin = identity.prelogin(&urls.identity, &email_login)?;
                    let base_kdf = prelogin
                        .to_kdf_config()
                        .ok_or_else(|| anyhow::anyhow!("unsupported KDF type: {}", prelogin.kdf))?;

                    let salt = prelogin.salt.clone().unwrap_or_else(|| email_kdf.clone());

                    let derived = derive_identity(&password, &salt, &base_kdf)?;
                    let server_hash = derived.server_password_hash_b64.clone();

                    let vault = VaultClient::default();
                    vault.send_email_login(
                        &urls.api,
                        &email_login,
                        &server_hash,
                        &device_identifier,
                        origin.as_deref(),
                    )?;

                    Ok(LoginWorkerResult::NeedTwoFactor {
                        _providers: vec!["1".to_string()],
                        message: "Verification code sent to your email".to_string(),
                        device_verification: false,
                    })
                })()
            })) {
                Ok(r) => match r {
                    Ok(v) => v,
                    Err(e) => LoginWorkerResult::Err(format!("send-email error: {e:#}")),
                },
                Err(_) => LoginWorkerResult::Err("send-email worker panicked".to_string()),
            };

            let _ = tx.send(result);
        });
    }

    fn reset_to_logged_out(&mut self, delete_session_file: bool) {
        if delete_session_file {
            Self::delete_persisted_session_file();
        }

        self.lock_keys = None;

        self.login.password.clear();
        self.session = None;
        self.sync_state = SyncState::Idle;
        self.sync_rx = None;
        self.vault_folders.clear();
        self.vault_items.clear();
        self.vault_ui.selected_item_id = None;
        self.vault_ui.selected_folder = VaultFolderFilter::AllItems;
        self.vault_ui.user_selected_folder = false;
        self.vault_ui.user_selected_item = false;
        self.vault_ui.show_password = false;
        self.vault_ui.password_clipboard_clear_at = None;
        self.details_mode = DetailsMode::View;
        self.route = AppRoute::LoggedOut;

        self.login_focus = LoginFocus::Email;
    }

    fn selected_item(&self) -> Option<&VaultItem> {
        let id = self.vault_ui.selected_item_id.as_deref()?;
        self.vault_items.iter().find(|it| it.id == id)
    }

    fn visible_items(&self) -> Vec<&VaultItem> {
        let query = self.vault_ui.search.trim().to_lowercase();

        self.vault_items
            .iter()
            .filter(|item| {
                let matches_folder = match &self.vault_ui.selected_folder {
                    VaultFolderFilter::AllItems => true,
                    VaultFolderFilter::Favorites => item.favorite,
                    VaultFolderFilter::Type(t) => item.item_type == *t,
                    VaultFolderFilter::Folder(folder_id) => {
                        item.folder_id.as_deref() == Some(folder_id.as_str())
                    }
                };
                if !matches_folder {
                    return false;
                }

                if query.is_empty() {
                    return true;
                }

                let mut hay = item.name.to_lowercase();
                if let Some(u) = &item.username {
                    hay.push(' ');
                    hay.push_str(&u.to_lowercase());
                }
                hay.contains(&query)
            })
            .collect()
    }

    fn start_new_item(&mut self) {
        self.vault_ui.selected_item_id = None;
        self.vault_ui.show_password = false;
        let draft = EditDraft::new_login();
        self.edit_notes_content = Some(iced::widget::text_editor::Content::with_text(&draft.notes));
        self.details_mode = DetailsMode::Edit {
            draft: Box::new(draft),
            is_new: true,
            confirm_delete: false,
        };
    }

    fn start_edit_selected_item(&mut self) {
        let Some(item) = self.selected_item().cloned() else {
            return;
        };
        self.vault_ui.show_password = false;
        let draft = EditDraft::from_item(&item);
        self.edit_notes_content = Some(iced::widget::text_editor::Content::with_text(&draft.notes));
        self.details_mode = DetailsMode::Edit {
            draft: Box::new(draft),
            is_new: false,
            confirm_delete: false,
        };
    }

    fn pickable_item_types() -> Vec<VaultItemType> {
        vec![
            VaultItemType::Login,
            VaultItemType::SecureNote,
            VaultItemType::Card,
            VaultItemType::Identity,
            VaultItemType::SshKey,
        ]
    }
}

impl BwClientIcedApp {
    fn boot() -> Self {
        let settings = Self::load_settings();

        let mut app = Self {
            route: AppRoute::LoggedOut,

            server: ServerConfig::default(),
            login: LoginForm {
                stay_logged_in: settings.stay_logged_in,
                ..LoginForm::default()
            },
            login_state: LoginState::Idle,
            login_rx: None,

            device_identifier: Self::load_or_create_device_identifier(),

            persisted_login: settings.login.clone(),
            lock_keys: None,

            unlock_password: String::new(),
            unlock_error: None,

            session: None,

            sync_state: SyncState::Idle,
            sync_rx: None,

            item_op_state: ItemOpState::Idle,
            item_op_rx: None,
            pending_select_id: None,

            vault_ui: VaultUiState::default(),
            vault_folders: Vec::new(),
            vault_items: Vec::new(),
            details_mode: DetailsMode::View,

            theme_mode: settings.theme,

            pwgen_open: false,
            pwgen_options: settings.password_generator,
            pwgen_password: String::new(),
            pwgen_error: None,

            about_open: false,

            unix_now: Self::now_unix(),

            ui_font: Self::default_ui_font(),

            login_focus: LoginFocus::Email,
            login_custom_base_url_id: iced::widget::Id::unique(),
            login_email_id: iced::widget::Id::unique(),
            login_password_id: iced::widget::Id::unique(),
            login_new_device_otp_id: iced::widget::Id::unique(),
            login_two_factor_code_id: iced::widget::Id::unique(),

            unlock_password_id: iced::widget::Id::unique(),

            // edit ids
            edit_name_id: iced::widget::Id::unique(),
            edit_username_id: iced::widget::Id::unique(),
            edit_password_id: iced::widget::Id::unique(),
            edit_totp_id: iced::widget::Id::unique(),
            edit_uris_id: iced::widget::Id::unique(),

            edit_ident_title_id: iced::widget::Id::unique(),
            edit_ident_first_id: iced::widget::Id::unique(),
            edit_ident_middle_id: iced::widget::Id::unique(),
            edit_ident_last_id: iced::widget::Id::unique(),
            edit_ident_company_id: iced::widget::Id::unique(),
            edit_ident_username_id: iced::widget::Id::unique(),
            edit_ident_email_id: iced::widget::Id::unique(),
            edit_ident_phone_id: iced::widget::Id::unique(),
            edit_ident_address1_id: iced::widget::Id::unique(),
            edit_ident_address2_id: iced::widget::Id::unique(),
            edit_ident_address3_id: iced::widget::Id::unique(),
            edit_ident_city_id: iced::widget::Id::unique(),
            edit_ident_state_id: iced::widget::Id::unique(),
            edit_ident_postal_id: iced::widget::Id::unique(),
            edit_ident_country_id: iced::widget::Id::unique(),
            edit_ident_ssn_id: iced::widget::Id::unique(),
            edit_ident_passport_id: iced::widget::Id::unique(),
            edit_ident_license_id: iced::widget::Id::unique(),

            edit_last_focused_id: None,

            edit_notes_content: None,
        };

        if let Some(login) = &app.persisted_login {
            app.server = login.server.clone();
            app.login.email = login.email.clone();
        }

        if app.login.stay_logged_in {
            if let Some(persisted) = Self::load_persisted_session()
                && let Ok(user_key_bytes) = STANDARD.decode(persisted.user_key_b64)
                && let Ok(user_key_64) = <[u8; 64]>::try_from(user_key_bytes.as_slice())
            {
                app.server = persisted.server;
                app.session = Some(Session {
                    access_token: persisted.access_token,
                    user_key: Keys::from_64(user_key_64),
                });
                app.route = AppRoute::Vault;
            }
        } else if app.persisted_login.is_some() && Self::load_persisted_data_encrypted().is_some() {
            app.route = AppRoute::Locked;
        }

        app
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            iced::time::every(Duration::from_millis(200)).map(|_| Message::Tick),
            iced::event::listen().map(Message::Event),
        ])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        let mut commands: Vec<Task<Message>> = Vec::new();

        match message {
            Message::Event(event) => {
                if self.route == AppRoute::LoggedOut {
                    if let iced::event::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                        key,
                        modifiers,
                        ..
                    }) = event
                        && key == iced::keyboard::Key::Named(iced::keyboard::key::Named::Tab)
                    {
                        commands.push(self.focus_next_login(modifiers.shift()));
                    }
                } else if self.route == AppRoute::Locked {
                    if let iced::event::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                        key,
                        ..
                    }) = event
                        && key == iced::keyboard::Key::Named(iced::keyboard::key::Named::Enter)
                    {
                        commands.push(Task::perform(async {}, |_| Message::UnlockPressed));
                    }
                } else if self.route == AppRoute::Vault
                    && let iced::event::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                        key,
                        modifiers,
                        ..
                    }) = event
                    && key == iced::keyboard::Key::Named(iced::keyboard::key::Named::Tab)
                {
                    // If editing, cycle edit fields; otherwise cycle within selected column
                    if let DetailsMode::Edit { draft, .. } = &self.details_mode {
                        commands.push(self.focus_next_edit(modifiers.shift(), draft.item_type));
                    } else if self.vault_ui.user_selected_folder {
                        commands.push(self.focus_next_folder(modifiers.shift()));
                    } else if self.vault_ui.user_selected_item {
                        commands.push(self.focus_next_item(modifiers.shift()));
                    }
                }
            }
            Message::Tick => {
                self.unix_now = Self::now_unix();

                self.poll_login();
                self.poll_sync();
                self.poll_item_op();

                if self.route == AppRoute::Vault {
                    self.ensure_sync_started();
                }

                if let Some(deadline) = self.vault_ui.password_clipboard_clear_at
                    && Instant::now() >= deadline
                {
                    self.vault_ui.password_clipboard_clear_at = None;
                    commands.push(iced::clipboard::write(String::new()));
                }
            }

            Message::ThemeToggle => {
                self.theme_mode = match self.theme_mode {
                    ThemeMode::Light => ThemeMode::Dark,
                    ThemeMode::Dark => ThemeMode::Light,
                };
                self.save_settings();
            }

            Message::ServerModeChanged(mode) => {
                self.server.mode = mode;
            }
            Message::OfficialRegionChanged(region) => {
                self.server.official_region = region;
            }
            Message::CustomBaseUrlChanged(s) => {
                self.server.custom_base_url = s;
                self.login_focus = LoginFocus::CustomBaseUrl;
            }

            Message::LoginEmailChanged(s) => {
                self.login.email = s;
                self.login_focus = LoginFocus::Email;
            }
            Message::LoginPasswordChanged(s) => {
                self.login.password = s;
                self.login_focus = LoginFocus::Password;
            }
            Message::LoginNewDeviceOtpChanged(s) => {
                self.login.new_device_otp = s;
                self.login_focus = LoginFocus::NewDeviceOtp;
            }

            Message::LoginStayLoggedInToggled(v) => {
                self.login.stay_logged_in = v;
                self.save_settings();
            }

            Message::LoginContinuePressed => {
                let can_continue = !self.login.email.trim().is_empty() && !self.login.password.is_empty();
                let is_in_progress = matches!(self.login_state, LoginState::InProgress { .. });

                if can_continue && !is_in_progress {
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.login_state = LoginState::InProgress {
                        started_at: Instant::now(),
                    };
                    self.login_rx = Some(rx);
                    self.start_login_with_2fa(tx, false);
                }
            }

            Message::TwoFactorProviderChanged(p) => {
                self.login.two_factor_provider = Some(p);
            }
            Message::TwoFactorCodeChanged(s) => {
                self.login.two_factor_code = s;
                self.login_focus = LoginFocus::TwoFactorCode;
            }
            Message::TwoFactorSendCodePressed => {
                if self.login.two_factor_provider.is_some() {
                    self.login.two_factor_code.clear();
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.login_state = LoginState::InProgress {
                        started_at: Instant::now(),
                    };
                    self.login_rx = Some(rx);
                    self.start_send_email_2fa(tx);
                }
            }
            Message::TwoFactorSubmitPressed => {
                let is_in_progress = matches!(self.login_state, LoginState::InProgress { .. });
                if !is_in_progress && !self.login.two_factor_code.trim().is_empty() {
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.login_state = LoginState::InProgress {
                        started_at: Instant::now(),
                    };
                    self.login_rx = Some(rx);
                    self.start_login_with_2fa(tx, false);
                }
            }

            Message::VaultSearchChanged(s) => self.vault_ui.search = s,
            Message::VaultSelectFolder(f) => {
                self.vault_ui.selected_folder = f;
                self.vault_ui.user_selected_folder = true;
                self.vault_ui.selected_item_id = None;
                self.vault_ui.user_selected_item = false;
                self.vault_ui.show_password = false;
                self.details_mode = DetailsMode::View;
            }
            Message::VaultSelectItem(id) => {
                self.vault_ui.selected_item_id = Some(id);
                self.vault_ui.user_selected_item = true;
                self.vault_ui.user_selected_folder = false;
                self.vault_ui.show_password = false;
                self.details_mode = DetailsMode::View;
            }

            Message::VaultSyncPressed => {
                let sync_in_progress = matches!(self.sync_state, SyncState::InProgress { .. });
                if !sync_in_progress {
                    self.sync_state = SyncState::Idle;
                    self.sync_rx = None;
                }
            }

            Message::VaultLockPressed => {
                if !self.login.stay_logged_in {
                    if let Some(session) = &self.session {
                        self.save_persisted_data(session);
                    }

                    self.session = None;
                    self.sync_state = SyncState::Idle;
                    self.sync_rx = None;
                    self.vault_folders.clear();
                    self.vault_items.clear();
                    self.vault_ui.selected_item_id = None;
                    self.vault_ui.selected_folder = VaultFolderFilter::AllItems;
                    self.vault_ui.user_selected_folder = false;
                    self.vault_ui.user_selected_item = false;
                    self.vault_ui.show_password = false;
                    self.vault_ui.password_clipboard_clear_at = None;
                    self.details_mode = DetailsMode::View;
                    self.unlock_password.clear();
                    self.unlock_error = None;
                    self.lock_keys = None;
                    self.route = AppRoute::Locked;
                } else {
                    self.reset_to_logged_out(false);
                }
            }
            Message::VaultLogoutPressed => {
                Self::delete_persisted_data_file();
                self.persisted_login = None;
                self.login.stay_logged_in = false;
                self.save_settings();
                self.reset_to_logged_out(true);
            }

            Message::UnlockPasswordChanged(s) => {
                self.unlock_password = s;
            }
            Message::UnlockPressed => {
                self.try_unlock();
            }
            Message::LockedLogoutPressed => {
                Self::delete_persisted_data_file();
                self.persisted_login = None;
                self.login.stay_logged_in = false;
                self.save_settings();
                self.reset_to_logged_out(true);
            }

            Message::VaultNewItemPressed => self.start_new_item(),
            Message::VaultEditItemPressed => self.start_edit_selected_item(),
            Message::VaultCancelEditPressed => {
                self.details_mode = DetailsMode::View;
                self.edit_notes_content = None;
            }
            Message::VaultSaveItemPressed => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    // If we have an editor content, sync it back into the draft.notes
                    if let Some(content) = &mut self.edit_notes_content {
                        let mut lines: Vec<String> = Vec::new();
                        for i in 0..content.line_count() {
                            if let Some(line) = content.line(i) {
                                lines.push(line.text.into_owned());
                            }
                        }
                        draft.notes = lines.join("\n");
                    }

                    let vault_draft = draft.to_vault_draft();
                    if vault_draft.name.trim().is_empty() {
                        self.item_op_state = ItemOpState::Error("Name is required".to_string());
                    } else {
                        self.start_item_op(ItemOp::Upsert(Box::new(vault_draft)));
                    }
                }
            }
            Message::VaultDeleteItemPressed => {
                if let DetailsMode::Edit {
                    draft,
                    confirm_delete,
                    ..
                } = &self.details_mode
                {
                    if !*confirm_delete {
                        // do nothing until confirmed
                    } else if let Some(id) = &draft.id {
                        self.start_item_op(ItemOp::Delete { id: id.clone() });
                    }
                }
            }
            Message::VaultConfirmDeleteToggled(v) => {
                if let DetailsMode::Edit { confirm_delete, .. } = &mut self.details_mode {
                    *confirm_delete = v;
                }
            }

            Message::EditGeneratePassword => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    match password_generator::generate(&self.pwgen_options) {
                        Ok(pw) => draft.password = pw,
                        Err(e) => self.pwgen_error = Some(e),
                    }
                }
            }

            Message::EditNotesAction(action) => {
                if let Some(content) = &mut self.edit_notes_content {
                    content.perform(action);
                    // keep draft notes in sync for previews
                    if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                        let mut lines: Vec<String> = Vec::new();
                        for i in 0..content.line_count() {
                            if let Some(line) = content.line(i) {
                                lines.push(line.text.into_owned());
                            }
                        }
                        draft.notes = lines.join("\n");
                    }
                }
            }
            Message::EditItemTypeChanged(t) => {
                if let DetailsMode::Edit { draft, is_new, .. } = &mut self.details_mode
                    && *is_new
                {
                    draft.item_type = t;
                    // clear type-specific fields
                    draft.username.clear();
                    draft.password.clear();
                    draft.totp.clear();
                    draft.uris.clear();
                    draft.cardholder_name.clear();
                    draft.card_brand.clear();
                    draft.card_number.clear();
                    draft.card_exp_month.clear();
                    draft.card_exp_year.clear();
                    draft.card_code.clear();
                    draft.ident_title.clear();
                    draft.ident_first.clear();
                    draft.ident_middle.clear();
                    draft.ident_last.clear();
                    draft.ident_company.clear();
                    draft.ident_email.clear();
                    draft.ident_phone.clear();
                    draft.ident_username.clear();
                    draft.ident_address1.clear();
                    draft.ident_address2.clear();
                    draft.ident_address3.clear();
                    draft.ident_city.clear();
                    draft.ident_state.clear();
                    draft.ident_postal.clear();
                    draft.ident_country.clear();
                    draft.ident_ssn.clear();
                    draft.ident_passport.clear();
                    draft.ident_license.clear();
                    draft.ssh_private.clear();
                    draft.ssh_public.clear();
                    draft.ssh_fingerprint.clear();
                    self.vault_ui.show_password = false;
                }
            }
            Message::EditFolderChanged(fid) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.folder_id = fid;
                }
            }
            Message::EditFavoriteToggled(v) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.favorite = v;
                }
            }

            Message::EditNameChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.name = s;
                    self.edit_last_focused_id = Some(self.edit_name_id.clone());
                }
            }
            Message::EditUsernameChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.username = s;
                    self.edit_last_focused_id = Some(self.edit_username_id.clone());
                }
            }
            Message::EditPasswordChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.password = s;
                    self.edit_last_focused_id = Some(self.edit_password_id.clone());
                }
            }
            Message::EditTotpChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.totp = s;
                    self.edit_last_focused_id = Some(self.edit_totp_id.clone());
                }
            }
            Message::EditUrisChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.uris = s;
                    self.edit_last_focused_id = Some(self.edit_uris_id.clone());
                }
            }
            Message::EditNotesChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.notes = s;
                }
            }

            Message::EditCardholderChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.cardholder_name = s;
                }
            }
            Message::EditCardBrandChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.card_brand = s;
                }
            }
            Message::EditCardNumberChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.card_number = s;
                }
            }
            Message::EditCardExpMonthChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.card_exp_month = s;
                }
            }
            Message::EditCardExpYearChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.card_exp_year = s;
                }
            }
            Message::EditCardCodeChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.card_code = s;
                }
            }

            Message::EditIdentTitleChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_title = s;
                    self.edit_last_focused_id = Some(self.edit_ident_title_id.clone());
                }
            }
            Message::EditIdentFirstChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_first = s;
                    self.edit_last_focused_id = Some(self.edit_ident_first_id.clone());
                }
            }
            Message::EditIdentMiddleChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_middle = s;
                    self.edit_last_focused_id = Some(self.edit_ident_middle_id.clone());
                }
            }
            Message::EditIdentLastChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_last = s;
                    self.edit_last_focused_id = Some(self.edit_ident_last_id.clone());
                }
            }
            Message::EditIdentCompanyChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_company = s;
                    self.edit_last_focused_id = Some(self.edit_ident_company_id.clone());
                }
            }
            Message::EditIdentEmailChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_email = s;
                    self.edit_last_focused_id = Some(self.edit_ident_email_id.clone());
                }
            }
            Message::EditIdentPhoneChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_phone = s;
                    self.edit_last_focused_id = Some(self.edit_ident_phone_id.clone());
                }
            }
            Message::EditIdentUsernameChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_username = s;
                    self.edit_last_focused_id = Some(self.edit_ident_username_id.clone());
                }
            }
            Message::EditIdentAddress1Changed(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_address1 = s;
                    self.edit_last_focused_id = Some(self.edit_ident_address1_id.clone());
                }
            }
            Message::EditIdentAddress2Changed(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_address2 = s;
                    self.edit_last_focused_id = Some(self.edit_ident_address2_id.clone());
                }
            }
            Message::EditIdentAddress3Changed(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_address3 = s;
                    self.edit_last_focused_id = Some(self.edit_ident_address3_id.clone());
                }
            }
            Message::EditIdentCityChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_city = s;
                    self.edit_last_focused_id = Some(self.edit_ident_city_id.clone());
                }
            }
            Message::EditIdentStateChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_state = s;
                    self.edit_last_focused_id = Some(self.edit_ident_state_id.clone());
                }
            }
            Message::EditIdentPostalChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_postal = s;
                    self.edit_last_focused_id = Some(self.edit_ident_postal_id.clone());
                }
            }
            Message::EditIdentCountryChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_country = s;
                    self.edit_last_focused_id = Some(self.edit_ident_country_id.clone());
                }
            }
            Message::EditIdentSsnChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_ssn = s;
                    self.edit_last_focused_id = Some(self.edit_ident_ssn_id.clone());
                }
            }
            Message::EditIdentPassportChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_passport = s;
                    self.edit_last_focused_id = Some(self.edit_ident_passport_id.clone());
                }
            }
            Message::EditIdentLicenseChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ident_license = s;
                    self.edit_last_focused_id = Some(self.edit_ident_license_id.clone());
                }
            }

            Message::EditSshPrivateChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ssh_private = s;
                }
            }
            Message::EditSshPublicChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ssh_public = s;
                }
            }
            Message::EditSshFingerprintChanged(s) => {
                if let DetailsMode::Edit { draft, .. } = &mut self.details_mode {
                    draft.ssh_fingerprint = s;
                }
            }

            Message::ToggleShowPassword => {
                self.vault_ui.show_password = !self.vault_ui.show_password;
            }
            Message::ToggleAutoClearPassword(v) => {
                self.vault_ui.clear_password_clipboard_after_30s = v;
            }

            Message::PwGenToggle => {
                self.pwgen_open = !self.pwgen_open;
                if self.pwgen_open && self.pwgen_password.is_empty() {
                    match password_generator::generate(&self.pwgen_options) {
                        Ok(p) => {
                            self.pwgen_password = p;
                            self.pwgen_error = None;
                        }
                        Err(e) => {
                            self.pwgen_error = Some(e);
                        }
                    }
                }
            }
            Message::PwGenRegenerate => {
                match password_generator::generate(&self.pwgen_options) {
                    Ok(p) => {
                        self.pwgen_password = p;
                        self.pwgen_error = None;
                    }
                    Err(e) => {
                        self.pwgen_error = Some(e);
                    }
                }
            }
            Message::PwGenCopy => {
                if !self.pwgen_password.is_empty() {
                    commands.push(iced::clipboard::write(self.pwgen_password.clone()));
                }
            }
            Message::PwGenLengthChanged(v) => {
                self.pwgen_options.length = v;
                self.save_settings();
            }
            Message::PwGenIncludeUpper(v) => {
                self.pwgen_options.include_upper = v;
                self.save_settings();
            }
            Message::PwGenIncludeLower(v) => {
                self.pwgen_options.include_lower = v;
                self.save_settings();
            }
            Message::PwGenIncludeDigits(v) => {
                self.pwgen_options.include_digits = v;
                self.save_settings();
            }
            Message::PwGenIncludeSpecial(v) => {
                self.pwgen_options.include_special = v;
                self.save_settings();
            }
            Message::PwGenMinNumbersChanged(v) => {
                self.pwgen_options.min_numbers = v;
                self.save_settings();
            }
            Message::PwGenMinSpecialChanged(v) => {
                self.pwgen_options.min_special = v;
                self.save_settings();
            }

            Message::AboutToggle => {
                self.about_open = !self.about_open;
            }

            Message::CopyToClipboard(s) => {
                commands.push(iced::clipboard::write(s));
            }
        }

        Task::batch(commands)
    }
}

impl std::fmt::Display for ServerMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerMode::Official => write!(f, "Official"),
            ServerMode::Custom => write!(f, "Custom"),
        }
    }
}

impl std::fmt::Display for OfficialRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OfficialRegion::Com => write!(f, "Com"),
            OfficialRegion::Eu => write!(f, "Eu"),
        }
    }
}

impl std::fmt::Display for VaultItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl Drop for BwClientIcedApp {
    fn drop(&mut self) {
        if !self.login.stay_logged_in {
            if let Some(session) = &self.session {
                self.save_persisted_data(session);
            }
        }
    }
}