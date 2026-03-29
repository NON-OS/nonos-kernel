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

use uefi::prelude::*;
use uefi::proto::console::text::{Input, Key, ScanCode};

use super::keys::KeyAction;

pub fn poll_input(bs: &BootServices) -> KeyAction {
    let handle = match bs.get_handle_for_protocol::<Input>() {
        Ok(h) => h,
        Err(_) => return KeyAction::None,
    };

    let mut input = match bs.open_protocol_exclusive::<Input>(handle) {
        Ok(i) => i,
        Err(_) => return KeyAction::None,
    };

    match input.read_key() {
        Ok(Some(key)) => match key {
            Key::Special(sc) => KeyAction::from_scancode(scancode_to_u16(sc)),
            Key::Printable(ch) => {
                if let Some(c) = char::from_u32(u16::from(ch) as u32) {
                    KeyAction::from_char(c)
                } else {
                    KeyAction::None
                }
            }
        },
        _ => KeyAction::None,
    }
}

fn scancode_to_u16(sc: ScanCode) -> u16 {
    match sc {
        ScanCode::UP => 1,
        ScanCode::DOWN => 2,
        ScanCode::ESCAPE => 23,
        ScanCode::FUNCTION_1 => 11,
        ScanCode::FUNCTION_10 => 20,
        _ => 0,
    }
}
