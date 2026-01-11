# bwclient

🔧 简要说明

`bwclient` 是一个用 Rust + `iced` 构建的桌面客户端（GUI），包含与密码/认证相关的功能模块（例如 TOTP、密码生成、Vault/API 客户端、加密模块等）。

## 当前实现状态 ✅
- GUI：基于 `iced`，已实现基本界面框架（`iced_app.rs`、`view.rs`）。
- 功能模块：包含 `api`, `totp`, `password_generator`, `crypto` 等主要模块。
- 平台：已在 workflow 中支持 Windows / macOS / Linux 的编译与打包（Release 工作流会在打 `tag` 时触发并把二进制附到 GitHub Release）。
- macOS：工作流会生成 `.app` + `.dmg`（可双击运行）。

## 基本使用（开发 / 本地构建）
- 开发运行（调试）：

```bash
# 运行（会启动 GUI）
cargo run
```

- 本地 release 构建：

```bash
cargo build --release
# 输出二进制位于 target/release/bwclient
# Linux/macOS: ./target/release/bwclient
# Windows: target\release\bwclient.exe
```

- 触发 GitHub Release（仓库会自动构建并上传对应平台的打包产物）：

```bash
# 创建并推送 tag（例如 v0.1.0）来触发 Release 工作流
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

> 更详细的触发/重触发方法请参阅 `docs/releasing.md`。

## macOS 双击运行说明
- Release 工作流会生成 `.app` 包并打成 `.dmg`，用户下载并挂载 `.dmg` 后，可直接双击 `bwclient.app` 以启动 GUI。
- 如果你希望本地也能直接创建 `.app`，可在 mac 上运行打包脚本（或使用 Xcode 的打包工具链）。

## 未来 TODOs 📝
- [ ] 在 `push` 到 `main` 时也执行构建以便持续集成（当前仅在 tag 时上传 Release）。
- [ ] 添加自动化测试（单元/集成测试）并在 CI 中运行。
- [ ] 为 macOS 做代码签名和 Notarization（便于分发与信任）。
- [ ] 提供平台原生安装包（Windows MSI/NSIS, macOS PKG/ZIP/Notarized DMG, Linux .deb/.rpm）。
- [ ] 自动化图标制作与 `app.icns` 生成，并把它加入 mac bundle。
- [ ] 增加自动化发布签名（GPG / 签名二进制）以保障发行完整性。
- [ ] 增强跨架构构建（例如 macOS aarch64 + x86_64 / universal）。

## 贡献
- 欢迎提交 issue 或 PR，描述建议或 Bug。提交前请先运行 `cargo fmt` 和 `cargo clippy`（如果适用）。

---

更多细节：参阅 `docs/releasing.md`（发布/触发 CI 的详细步骤）。
