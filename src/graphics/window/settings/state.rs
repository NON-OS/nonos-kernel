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

pub(crate) const SIDEBAR_WIDTH: u32 = 120;
pub(crate) const PAGE_PRIVACY: u8 = 0;
pub(crate) const PAGE_NETWORK: u8 = 1;
pub(crate) const PAGE_APPEARANCE: u8 = 2;
pub(crate) const PAGE_SYSTEM: u8 = 3;
pub(crate) const PAGE_POWER: u8 = 4;

pub(crate) static SETTING_PRIVACY: AtomicBool = AtomicBool::new(true);
pub static SETTING_ANON_NET: AtomicBool = AtomicBool::new(true);
pub(crate) static SETTING_ZERO_STATE: AtomicBool = AtomicBool::new(true);
pub(crate) static SETTING_AUTO_WIPE: AtomicBool = AtomicBool::new(false);
pub(crate) static SETTING_DARK_THEME: AtomicBool = AtomicBool::new(true);

pub(crate) static SETTING_ANYONE_ENABLED: AtomicBool = AtomicBool::new(true);
pub(crate) static SETTING_PRIVACY_MODE: AtomicU8 = AtomicU8::new(1);
pub(crate) static SETTING_DHCP_ENABLED: AtomicBool = AtomicBool::new(true);

pub(crate) static SETTINGS_PAGE: AtomicU8 = AtomicU8::new(0);

pub(crate) fn get_page() -> u8 {
    SETTINGS_PAGE.load(Ordering::Relaxed)
}

pub(crate) fn set_page(page: u8) {
    if page <= PAGE_POWER {
        SETTINGS_PAGE.store(page, Ordering::Relaxed);
    }
}

pub(crate) const PAGE_COUNT: u8 = 5;

pub(crate) fn toggle_setting(setting: &AtomicBool) -> bool {
    let current = setting.load(Ordering::Relaxed);
    setting.store(!current, Ordering::Relaxed);
    !current
}

pub(crate) fn is_anyone_enabled() -> bool {
    SETTING_ANYONE_ENABLED.load(Ordering::Relaxed)
}

pub(crate) fn is_privacy_enabled() -> bool {
    SETTING_PRIVACY.load(Ordering::Relaxed)
}

pub(crate) fn is_zero_state_enabled() -> bool {
    SETTING_ZERO_STATE.load(Ordering::Relaxed)
}

pub(crate) fn is_dark_theme() -> bool {
    SETTING_DARK_THEME.load(Ordering::Relaxed)
}

pub fn is_dhcp_enabled() -> bool {
    SETTING_DHCP_ENABLED.load(Ordering::Relaxed)
}

pub(crate) fn get_privacy_mode() -> u8 {
    SETTING_PRIVACY_MODE.load(Ordering::Relaxed)
}

pub(crate) fn set_privacy_mode(mode: u8) {
    if mode < 4 {
        SETTING_PRIVACY_MODE.store(mode, Ordering::Relaxed);
    }
}

pub(crate) fn set_dhcp_enabled(enabled: bool) {
    SETTING_DHCP_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn reset_render_state() {
    SETTINGS_PAGE.store(0, Ordering::Relaxed);
}

pub fn reset_all() {
    reset_render_state();
    super::appearance::state::reset_state();
    super::render::reset_sync_flag();
}
