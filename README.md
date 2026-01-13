# bwclient

🔧 Brief Description

`bwclient` is a desktop client (GUI) built with Rust + `iced`, including password/authentication-related functional modules (such as TOTP, password generation, Vault/API client, encryption modules, etc.).

## Current Implementation Status ✅
- GUI: Based on `iced`, basic interface framework implemented (`iced_app.rs`, `view.rs`).
- Functional Modules: Includes main modules such as `api`, `totp`, `password_generator`, `crypto`, etc.
- Platforms: Supports compilation and packaging for Windows / macOS / Linux in workflows (Release workflow triggers when tagging and attaches binaries to GitHub Release).
- macOS: Workflow generates `.app` + `.dmg` (double-click to run). may need with `sudo xattr -cr bwclient.app`

## Basic Usage (Development / Local Build)
- Development Run (Debug):

```bash
# Run (will start GUI)
cargo run
```

- Local Release Build:

```bash
cargo build --release
# Binary output located at target/release/bwclient
# Linux/macOS: ./target/release/bwclient
# Windows: target\release\bwclient.exe
```

- Trigger GitHub Release (Repository will automatically build and upload packaged products for corresponding platforms):

```bash
# Create and push tag (e.g., v0.1.0) to trigger Release workflow
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

> For more detailed trigger/re-trigger methods, please refer to `docs/releasing.md`.

## macOS Double-Click Run Instructions
- The Release workflow generates `.app` package and packs it into `.dmg`. After downloading and mounting the `.dmg`, users can directly double-click `bwclient.app` to start the GUI.
- If you want to create `.app` locally, you can run the packaging script on macOS (or use Xcode's packaging toolchain). or `sudo xattr -cr bwclient.app`

## Contributing
- Welcome to submit issues or PRs, describing suggestions or bugs. Before submitting, please run `cargo fmt` and `cargo clippy` (if applicable).

---

More details: Refer to `docs/releasing.md` (detailed steps for release/triggering CI).
