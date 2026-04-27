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

use crate::graphics::window::settings::state::*;
use crate::sys::settings as sys_settings;
use core::sync::atomic::Ordering;

pub fn sync_from_system() {
    let settings = sys_settings::get();
    SETTING_NYM_ENABLED.store(settings.nym_enabled, Ordering::Relaxed);
    SETTING_PRIVACY.store(settings.anonymous_mode, Ordering::Relaxed);
    SETTING_ZERO_STATE.store(settings.auto_wipe, Ordering::Relaxed);
    SETTING_DARK_THEME.store(settings.theme == 0, Ordering::Relaxed);
}
