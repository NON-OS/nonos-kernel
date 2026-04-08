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

use crate::arch::x86_64::keyboard::error::KeymapError;
use crate::arch::x86_64::keyboard::layout::Layout;
use crate::arch::x86_64::keyboard::types::{KeyCode, KeyMapping};
use super::scan_extended::map_extended_scan_code;
use super::scan_standard::map_standard_scan_code;
use super::state::{get_extended_state, set_extended_state, update_modifiers, ExtendedState};

pub type KeymapResult<T> = Result<T, KeymapError>;

pub fn process_scan_code(scan_code: u8, layout: Layout) -> KeymapResult<Option<KeyMapping>> {
    let state = get_extended_state();
    match (state, scan_code) {
        (ExtendedState::None, 0xE0) => { set_extended_state(ExtendedState::E0Pending); return Ok(None); }
        (ExtendedState::None, 0xE1) => { set_extended_state(ExtendedState::E1Pending(1)); return Ok(None); }
        (ExtendedState::E1Pending(1), _) => { set_extended_state(ExtendedState::E1Pending(2)); return Ok(None); }
        (ExtendedState::E1Pending(_), _) => {
            set_extended_state(ExtendedState::None);
            return Ok(Some(KeyMapping::non_printable(KeyCode::Pause, true)));
        }
        _ => {}
    }
    let is_release = (scan_code & 0x80) != 0;
    let code = scan_code & 0x7F;
    if state == ExtendedState::E0Pending {
        set_extended_state(ExtendedState::None);
        update_modifiers(code, is_release, true);
        return Ok(Some(map_extended_scan_code(code)));
    }
    if code >= 0x60 && code != 0x7F { return Err(KeymapError::InvalidScanCode); }
    update_modifiers(code, is_release, false);
    Ok(Some(map_standard_scan_code(code, layout)))
}
