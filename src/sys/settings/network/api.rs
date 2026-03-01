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

use core::sync::atomic::Ordering;
use crate::network::boot_config::PrivacyMode;
use super::types::NetworkSettings;
use super::state::{NETWORK_SETTINGS, SETTINGS_MODIFIED};
use super::persist::load_from_disk;

pub fn init() {
    let _ = load_from_disk();
}

pub fn get_settings() -> NetworkSettings {
    NETWORK_SETTINGS.lock().clone()
}

pub fn update_settings(settings: NetworkSettings) {
    *NETWORK_SETTINGS.lock() = settings;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
}

pub fn get_privacy_mode() -> PrivacyMode {
    NETWORK_SETTINGS.lock().privacy_mode
}

pub fn set_privacy_mode(mode: PrivacyMode) {
    NETWORK_SETTINGS.lock().privacy_mode = mode;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);

    apply_privacy_mode(mode);
}

fn apply_privacy_mode(mode: PrivacyMode) {
    use crate::network::transparent::{self, InterceptorConfig};

    match mode {
        PrivacyMode::Standard => {
            transparent::shutdown_transparent_routing();
        }
        PrivacyMode::TorOnly | PrivacyMode::Maximum => {
            let config = InterceptorConfig {
                enabled: true,
                intercept_tcp: true,
                intercept_dns: mode == PrivacyMode::Maximum,
                bypass_local: mode != PrivacyMode::Maximum,
                ..InterceptorConfig::default()
            };
            let _ = transparent::init_transparent_routing(config);
        }
        PrivacyMode::Isolated => {
            transparent::shutdown_transparent_routing();
        }
    }
}

pub fn is_onion_enabled() -> bool {
    NETWORK_SETTINGS.lock().onion_enabled
}

pub fn set_onion_enabled(enabled: bool) {
    let mut settings = NETWORK_SETTINGS.lock();
    settings.onion_enabled = enabled;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);

    if enabled && settings.onion_auto_connect {
        if let Err(e) = crate::network::onion::init_onion_router() {
            crate::log_warn!("Failed to start onion router: {:?}", e);
        }
    }
}

pub fn is_socks_enabled() -> bool {
    NETWORK_SETTINGS.lock().socks_enabled
}

pub fn set_socks_enabled(enabled: bool) {
    let mut settings = NETWORK_SETTINGS.lock();
    settings.socks_enabled = enabled;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);

    if enabled {
        let _ = crate::network::socks::start_socks_server();
    } else {
        crate::network::socks::stop_socks_server();
    }
}

pub fn get_socks_port() -> u16 {
    NETWORK_SETTINGS.lock().socks_port
}

pub fn set_socks_port(port: u16) {
    NETWORK_SETTINGS.lock().socks_port = port;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
}

pub fn is_transparent_proxy_enabled() -> bool {
    NETWORK_SETTINGS.lock().transparent_proxy
}

pub fn set_transparent_proxy_enabled(enabled: bool) {
    use crate::network::transparent::InterceptorConfig;

    let mut settings = NETWORK_SETTINGS.lock();
    settings.transparent_proxy = enabled;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);

    if enabled {
        let config = InterceptorConfig {
            enabled: true,
            intercept_tcp: true,
            intercept_dns: settings.privacy_mode == PrivacyMode::Maximum,
            bypass_local: settings.privacy_mode != PrivacyMode::Maximum,
            ..InterceptorConfig::default()
        };
        let _ = crate::network::transparent::init_transparent_routing(config);
    } else {
        crate::network::transparent::shutdown_transparent_routing();
    }
}

pub fn is_mac_randomization_enabled() -> bool {
    NETWORK_SETTINGS.lock().randomize_mac
}

pub fn set_mac_randomization_enabled(enabled: bool) {
    NETWORK_SETTINGS.lock().randomize_mac = enabled;
    SETTINGS_MODIFIED.store(true, Ordering::SeqCst);
}
