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

mod page;
mod settings;

pub use page::{
    get_page, reset_render_state, set_page, PAGE_ACCESSIBILITY, PAGE_APPEARANCE, PAGE_COUNT,
    PAGE_DISPLAY, PAGE_KERNEL, PAGE_KEYBOARD, PAGE_LOCK, PAGE_MOUSE, PAGE_NETWORK, PAGE_POWER,
    PAGE_PRIVACY, PAGE_SOUND, PAGE_SYSTEM, SIDEBAR_WIDTH,
};

pub use settings::{
    get_privacy_mode, is_dark_theme, is_dhcp_enabled, is_nym_enabled, is_privacy_enabled,
    is_wifi_autoconnect, is_zero_state_enabled, set_dhcp_enabled, set_privacy_mode, toggle_setting,
    SETTING_ANON_NET, SETTING_AUTO_WIPE, SETTING_DARK_THEME, SETTING_DHCP_ENABLED,
    SETTING_NYM_ENABLED, SETTING_PRIVACY, SETTING_PRIVACY_MODE, SETTING_ZERO_STATE,
};

pub fn reset_all() {
    reset_render_state();
    super::appearance::state::reset_state();
    super::render::reset_sync_flag();
}
