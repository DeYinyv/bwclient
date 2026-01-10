#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod api;
mod iced_app;
mod crypto;
mod password_generator;
mod server;
mod totp;

fn main() -> iced::Result {
    iced_app::BwClientIcedApp::run()
}
