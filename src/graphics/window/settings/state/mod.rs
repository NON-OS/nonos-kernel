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
    get_page, set_page, reset_render_state,
    SIDEBAR_WIDTH, PAGE_PRIVACY, PAGE_NETWORK, PAGE_APPEARANCE, PAGE_SYSTEM, PAGE_POWER, PAGE_COUNT,
};

pub use settings::{
    SETTING_PRIVACY, SETTING_ANON_NET, SETTING_ZERO_STATE, SETTING_AUTO_WIPE, SETTING_DARK_THEME,
    SETTING_NYM_ENABLED, SETTING_PRIVACY_MODE, SETTING_DHCP_ENABLED,
    toggle_setting, is_nym_enabled, is_privacy_enabled, is_zero_state_enabled, is_dark_theme,
    is_dhcp_enabled, get_privacy_mode, set_privacy_mode, set_dhcp_enabled,
};

pub fn reset_all() {
    reset_render_state();
    super::appearance::state::reset_state();
    super::render::reset_sync_flag();
}
