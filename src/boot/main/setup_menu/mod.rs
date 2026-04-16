// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

mod brand;
mod render;
mod input;
mod state;
mod screens;

pub use state::SetupConfig;
use crate::graphics::framebuffer;
use crate::sys::settings;
use screens::Screen;

pub fn run_setup_menu() -> SetupConfig {
    crate::sys::serial::println(b"[SETUP] Starting NONOS Setup Menu");
    let mut config = SetupConfig::default();
    let mut current = screens::Screen::Welcome;
    framebuffer::clear(brand::BG_PRIMARY);
    framebuffer::swap_buffers();
    loop {
        current = screens::render_and_handle(&mut config, current);
        if current == Screen::Complete { break; }
        framebuffer::swap_buffers();
        for _ in 0..5000 { core::hint::spin_loop(); }
    }
    crate::sys::serial::println(b"[SETUP] Setup complete");
    config
}

pub fn needs_setup() -> bool { !state::is_setup_complete() }

pub fn apply_config(config: &SetupConfig) {
    crate::sys::serial::println(b"[SETUP] Applying config");
    let lang_id = match config.language_index {
        0 => 0, 1 => 3, 2 => 2, 3 => 1, 6 => 4, 7 => 5, _ => 0,
    };
    settings::set_language(lang_id);
    crate::locale::set_lang(crate::locale::Language::from(lang_id));
    if let Some(idx) = config.wallpaper_index {
        crate::graphics::backgrounds::set_current_wallpaper(idx);
        crate::sys::serial::println(b"[SETUP] Loading selected wallpaper");
        crate::graphics::backgrounds::try_load_wallpaper();
        crate::sys::serial::println(b"[SETUP] Wallpaper loaded");
    }
    settings::set_developer_mode(config.developer_mode);
    settings::set_hardware_crypto(config.hardware_crypto);
    crate::crypto::hardware_accel::set_enabled(config.hardware_crypto);
    settings::set_zk_attestation(config.zk_attestation);
    if config.generate_keys && !settings::system_keys_generated() {
        generate_system_keys();
        settings::set_system_keys_generated(true);
    }
    state::mark_setup_complete();
    crate::sys::serial::println(b"[SETUP] Config applied");
}

fn generate_system_keys() {
    extern crate alloc;
    use alloc::string::String;
    use crate::security::crypto::key_management::{generate_key, KeyType, KeyUsage};
    crate::sys::serial::println(b"[SETUP] Generating Ed25519 signing keypair");
    if let Ok(id) = generate_key(String::from("system_signing"), KeyType::Ed25519Signing, KeyUsage::signing(), 0) {
        crate::sys::serial::println(b"[SETUP] Ed25519 keypair stored");
        crate::log::info!("[SETUP] Signing key ID: {}", id);
    }
    crate::sys::serial::println(b"[SETUP] Generating X25519 key exchange keypair");
    if let Ok(id) = generate_key(String::from("system_exchange"), KeyType::X25519Exchange, KeyUsage::key_exchange(), 0) {
        crate::sys::serial::println(b"[SETUP] X25519 keypair stored");
        crate::log::info!("[SETUP] Exchange key ID: {}", id);
    }
    crate::sys::serial::println(b"[SETUP] System keys generated and stored securely");
}
