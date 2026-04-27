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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

pub static SETTING_PRIVACY: AtomicBool = AtomicBool::new(true);
pub static SETTING_ANON_NET: AtomicBool = AtomicBool::new(true);
pub static SETTING_ZERO_STATE: AtomicBool = AtomicBool::new(true);
pub static SETTING_AUTO_WIPE: AtomicBool = AtomicBool::new(false);
pub static SETTING_DARK_THEME: AtomicBool = AtomicBool::new(true);
pub static SETTING_NYM_ENABLED: AtomicBool = AtomicBool::new(true);
pub static SETTING_PRIVACY_MODE: AtomicU8 = AtomicU8::new(1);
pub static SETTING_DHCP_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn toggle_setting(setting: &AtomicBool) -> bool {
    let current = setting.load(Ordering::Relaxed);
    setting.store(!current, Ordering::Relaxed);
    !current
}

pub fn is_nym_enabled() -> bool {
    SETTING_NYM_ENABLED.load(Ordering::Relaxed)
}
pub fn is_privacy_enabled() -> bool {
    SETTING_PRIVACY.load(Ordering::Relaxed)
}
pub fn is_zero_state_enabled() -> bool {
    SETTING_ZERO_STATE.load(Ordering::Relaxed)
}
pub fn is_dark_theme() -> bool {
    SETTING_DARK_THEME.load(Ordering::Relaxed)
}
pub fn is_dhcp_enabled() -> bool {
    SETTING_DHCP_ENABLED.load(Ordering::Relaxed)
}

pub fn get_privacy_mode() -> u8 {
    SETTING_PRIVACY_MODE.load(Ordering::Relaxed)
}

pub fn set_privacy_mode(mode: u8) {
    if mode < 4 {
        SETTING_PRIVACY_MODE.store(mode, Ordering::Relaxed);
    }
}

pub fn set_dhcp_enabled(enabled: bool) {
    SETTING_DHCP_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_wifi_autoconnect() -> bool {
    crate::sys::settings::wifi_autoconnect()
}
