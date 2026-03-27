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

mod display;
mod input;
mod privacy;
mod system;

pub use display::{brightness, set_brightness, screen_timeout, set_screen_timeout};
pub use input::{mouse_sensitivity, set_mouse_sensitivity, keyboard_layout, set_keyboard_layout};
pub use input::{sound_enabled, set_sound_enabled};
pub use privacy::{anonymous_mode, set_anonymous_mode, anyone_enabled, set_anyone_enabled};
pub use privacy::{auto_wipe, set_auto_wipe};
pub use system::{theme, set_theme, timezone, set_timezone};
