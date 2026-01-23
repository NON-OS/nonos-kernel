// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod convert;
mod numpad;
mod scan;
mod state;
#[cfg(test)]
mod test

pub use convert::{ascii_to_keycode, keycode_to_ascii, keycode_to_ascii_with_mods};
pub use numpad::NumpadKey;
pub use scan::{map_scan_code, map_scan_code_full, process_scan_code, KeymapResult};
pub use state::{
    get_extended_state, get_modifiers, reset_extended_state, reset_modifiers, set_extended_state,
    set_modifiers, update_modifiers, ExtendedState,
};

pub use crate::arch::x86_64::keyboard::error::KeymapError;
pub use crate::arch::x86_64::keyboard::types::{KeyCode, KeyMapping, Modifiers, ScanCode};

pub type ModifierState = Modifiers;
