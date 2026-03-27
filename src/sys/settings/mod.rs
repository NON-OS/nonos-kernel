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

pub mod network;
mod types;
pub(crate) mod state;
mod api;
mod serialize;
mod persistence;
mod hostname;

pub use types::Settings;
pub use state::{init, get, get_mut, mark_modified, needs_save, reset_to_defaults};

pub use api::{
    brightness, set_brightness, screen_timeout, set_screen_timeout,
    mouse_sensitivity, set_mouse_sensitivity, keyboard_layout, set_keyboard_layout,
    sound_enabled, set_sound_enabled,
    anonymous_mode, set_anonymous_mode, anyone_enabled, set_anyone_enabled,
    auto_wipe, set_auto_wipe,
    theme, set_theme, timezone, set_timezone,
};

pub use persistence::{save_to_disk, load_from_disk, SETTINGS_FILENAME};
pub use serialize::{serialize, deserialize};

pub use hostname::{
    init as init_hostname, get as get_hostname, set as set_hostname,
    get_domain as get_domainname, set_domain as set_domainname,
};
