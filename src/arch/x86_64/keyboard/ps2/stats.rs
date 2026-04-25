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

use super::api::is_initialized;
use super::globals::{KEYBOARD, MOUSE};
use super::keyboard::ScanCodeSet;
use super::mouse::MouseType;

#[derive(Debug, Clone, Copy)]
pub struct Ps2Stats {
    pub initialized: bool,
    pub keyboard_detected: bool,
    pub mouse_detected: bool,
    pub mouse_type: Option<MouseType>,
    pub scancode_set: Option<ScanCodeSet>,
}

pub fn get_stats() -> Ps2Stats {
    let kb = KEYBOARD.lock();
    let m = MOUSE.lock();
    Ps2Stats {
        initialized: is_initialized(),
        keyboard_detected: kb.is_detected(),
        mouse_detected: m.is_detected(),
        mouse_type: if m.is_detected() { Some(m.mouse_type()) } else { None },
        scancode_set: if kb.is_detected() { Some(kb.scancode_set()) } else { None },
    }
}
