# bwclient

BwClient is a desktop Bitwarden client built with Rust + `iced`. It covers core capabilities including authentication, vault synchronization, local decryption and display, TOTP, password generation, and session persistence. It supports both self-hosted Bitwarden servers and the official Bitwarden cloud.

## 1. Project Overview

BwClientV1.0 is designed for desktop vault management scenarios. It provides a three-pane vault management interface, common item viewing and editing workflows, and practical day-to-day features such as a password generator and theme switching.

## UI Preview

### Windows

![BwClient Windows UI](img/windows.png)

### Linux

![BwClient Linux UI](img/linux.png)

## 2. Purpose

### 2.1 Feature Overview

BwClientV1.0 provides the following core use cases:

1. Secure login and key derivation: obtain KDF parameters through Bitwarden Prelogin, derive keys from the master password, authenticate with the server, and obtain access tokens.
2. Vault synchronization and local decrypted display: pull vault data from the server sync API, decrypt it locally, and present it in a structured format.
3. Three-pane vault management: uses a layout of "left category/folder pane + middle list pane + right detail pane" to improve item lookup and operation efficiency.
4. Common item operations: supports creating, editing, deleting, copying fields, and showing or hiding sensitive fields.
5. Password generator: includes a configurable password generator and provides one-click generation while editing login items.
6. Session and preference persistence: provides theme settings and session persistence for startup recovery, and supports cleanup on logout or lock.

Note: BwClientV1.0 primarily targets self-hosted/private deployments, but also supports the official Bitwarden cloud in Official mode.

- The login screen supports both Custom and Official modes, with Custom selected by default. In Official mode, the user can choose a region from the dropdown: Com or Eu.
- To improve compatibility with the official cloud, when Official mode is selected the client attempts to mimic browser behavior by submitting `client_id=web`, `deviceType=9`, `deviceName=chrome`, using a browser-style `User-Agent`, and attaching `Origin/Referer` when necessary to reduce the chance of being identified as Unknown Browser.

### 2.2 Feature List

The following list is organized from the end-user perspective to support acceptance, training, and screenshot documentation.

#### 2.2.1 Login and Server Configuration

- Self-hosted server Base URL input, with automatic derivation of `/identity` and `/api` service endpoints
- Server mode switching: Custom / Official (Com/Eu), with Custom as the default; Official mode enables browser emulation to improve compatibility
- Account login with Email + Master Password, with browser-like request behavior in Official mode to match the official cloud more closely
- Two-factor authentication (2FA) support:
  - Email 2FA (provider id 1 shown as Email): when the server requires 2FA, the UI displays the provider and offers a Send code button that triggers `/api/two-factor/send-email-login`. After receiving the email verification code, paste it into the Code field and click Submit 2FA. The client submits both `twoFactorToken` and `twoFactorCode`, and also supports `twoFactorRemember` to match official behavior.
  - New Device OTP: the login form still allows entering a New Device OTP when the server requires it.
- Login status feedback: in progress / success / failure reason

> Screenshot placeholder: login screen

#### 2.2.2 Session Management (Logout / Lock / Restore)

- Logout: clears the local session file and returns to the login screen
- Lock: clears only the in-memory session and returns to the login screen without deleting the saved session file
- Automatic restore on startup: if a saved session is detected, the app enters the vault screen directly on launch

> Screenshot placeholder: top toolbar - Logout/Lock

#### 2.2.3 Sync

- Automatic sync: triggered automatically after entering the vault screen
- Manual sync: triggered by the Sync button in the toolbar
- Sync status feedback: Idle / Syncing / Done (with synced item count) / Error

> Screenshot placeholder: sync status and Sync button

#### 2.2.4 Theme and Appearance

- Theme switching: Light / Dark
- Theme persistence: the previously selected theme is reused on the next startup

> Screenshot placeholder: theme switch button

#### 2.2.5 Vault Browsing (Left Pane)

- Preset filters: All items / Favorites
- Type filters: Login / Card / Identity / Note / SSH key
- Folder browsing: syncs folder list from the server and supports filtering by folder

> Screenshot placeholder: left pane - types and folders

#### 2.2.6 Search and List (Middle Pane)

- Search box: supports fuzzy matching by "name + username"
- List display:
  - Login: shows Name - Username
  - Non-login: shows Name - Type
- Clicking an item displays its details in the right pane

> Screenshot placeholder: search box and item list

#### 2.2.7 Item Detail View (Right Pane / View)

- View basic item information: name, type, favorite status, and folder if available
- Field copy actions: common fields provide Copy buttons, such as username, card number, or SSH key
- Sensitive field show/hide: for example, passwords and SSH private keys support Show/Hide
- TOTP display: login items can show the current verification code with an expiration countdown and one-click copy
- Notes display: the Notes field is readable in the detail view

> Screenshot placeholder: item detail - view mode

#### 2.2.8 Item Creation and Editing (Right Pane / Edit)

- Create item: top New button
- Edit item: Edit button on the detail page
- Save / Cancel
- Delete (`Delete...` -> `Confirm delete?`)
- New items support type selection: Login / Note / Card / Identity / SSH key
- Login items support editing or pasting TOTP secrets, which are encrypted and saved to the server

> Screenshot placeholder: item edit - basic fields

#### 2.2.9 Login Item

- Fields: Username, Password, TOTP, URLs (multi-line)
- Password show/hide
- Password copy
- One-click password generation (Gen): generates a password using the default generator settings and writes it into the Password field
- TOTP display in detail view:
  - Real-time current code
  - Expiration countdown, for example `Expires in 12s`
  - One-click copy of the current code
- TOTP editing in edit view: supports directly pasting either of the following formats
  - Base32 secret
  - `otpauth://totp/...`

> Screenshot placeholder: Login edit - Gen/Copy/Show/TOTP

> Screenshot placeholder: Login detail - TOTP countdown and Copy

#### 2.2.10 Note Item

- Field: Notes
- View and edit support

> Screenshot placeholder: Note detail/edit

#### 2.2.11 Card Item

- Fields: Cardholder, Brand, Number, Expiration, Security code
- Copy support for fields such as Number and Security code, depending on available UI buttons

> Screenshot placeholder: Card detail/edit

#### 2.2.12 Identity Item

- Fixed two-column layout, with at most two fields per row, avoiding misalignment caused by dynamic wrapping
- No Copy buttons in edit view, reducing accidental clicks and visual noise
- Field layout:
  - Title | First
  - Middle | Last
  - Company | User
  - Email
  - Phone
  - Address1
  - Address2 | Address3
  - City | State
  - Country | Postal
  - SSN
  - Passport | License

> Screenshot placeholder: Identity detail/edit with fixed layout

#### 2.2.13 SSH Key Item

- Fields: Fingerprint, Public key, Private key
- Copy support for Public key and Private key
- Private key Show/Hide support

> Screenshot placeholder: SSH key detail/edit

#### 2.2.14 Password Generator (Standalone Window)

- Standalone entry point: Password Generator in the toolbar
- Generated result: displays the generated password, with Copy and Regenerate actions
- Options:
  - Length, default 16
  - Include: A-Z enabled by default, a-z enabled by default, 0-9 enabled by default, `!@#$%^&*` disabled by default
  - Minimum numbers, default 3; disabled and treated as 0 when 0-9 is unchecked
  - Minimum special, default 3; disabled and treated as 0 when special characters are unchecked
- Option persistence: reuse the last saved configuration on the next startup

> Screenshot placeholder: password generator

## 3. Current Implementation Status

- GUI: desktop UI implemented with `iced`, with main UI logic located in `src/iced_app.rs` and `src/iced_app/view.rs`
- Functional modules: includes major modules such as `api`, `totp`, `password_generator`, and `crypto`
- Platform support: supports Windows, macOS, and Linux build and release workflows
- macOS: the Release workflow generates `.app` and `.dmg`

## 4. Development and Local Build

Development run:

```bash
cargo run
```

Local release build:

```bash
cargo build --release
# Binary output: target/release/bwclient
# Linux/macOS: ./target/release/bwclient
# Windows: target\release\bwclient.exe
```

Trigger GitHub Release:

```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

For more release details, refer to `docs/releasing.md`.

## 5. macOS Double-Click Launch Notes

- The Release workflow generates `.app` and packages it into `.dmg`. After mounting the `.dmg`, users can directly double-click `bwclient.app` to launch it.
- If the app is blocked by macOS security restrictions when opened locally, try running `sudo xattr -cr bwclient.app`.

## 6. Contributing

Issues and PRs are welcome. Before submitting changes, it is recommended to run:

```bash
cargo fmt
cargo clippy
```
