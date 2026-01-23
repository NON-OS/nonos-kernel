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

use super::types::{ModifierState, MOUSE_REPORT_MIN_SIZE, MOUSE_REPORT_SCROLL_SIZE, MAX_KEYS_PRESSED};
use super::usage::ERR_ROLLOVER;

pub fn parse_keyboard_report(report: &[u8; 8]) -> Option<u8> {
    for &keycode in &report[2..8] {
        if keycode != 0 && keycode != ERR_ROLLOVER {
            return Some(keycode);
        }
    }
    None
}

pub fn parse_keyboard_report_all(report: &[u8; 8]) -> [u8; MAX_KEYS_PRESSED] {
    let mut keys = [0u8; MAX_KEYS_PRESSED];
    let mut idx = 0;

    for &keycode in &report[2..8] {
        if keycode != 0 && keycode != ERR_ROLLOVER && idx < MAX_KEYS_PRESSED {
            keys[idx] = keycode;
            idx += 1;
        }
    }

    keys
}

pub fn parse_keyboard_modifiers(report: &[u8; 8]) -> ModifierState {
    ModifierState::from_byte(report[0])
}

pub fn parse_mouse_report(report: &[u8]) -> Option<(i16, i16, [bool; 3])> {
    if report.len() < MOUSE_REPORT_MIN_SIZE {
        return None;
    }

    let buttons = [
        (report[0] & 0x01) != 0,
        (report[0] & 0x02) != 0,
        (report[0] & 0x04) != 0,
    ];
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;

    Some((dx, dy, buttons))
}

pub fn parse_mouse_report_scroll(report: &[u8]) -> Option<(i16, i16, i8, [bool; 5])> {
    if report.len() < MOUSE_REPORT_SCROLL_SIZE {
        return None;
    }

    let buttons = [
        (report[0] & 0x01) != 0,
        (report[0] & 0x02) != 0,
        (report[0] & 0x04) != 0,
        (report[0] & 0x08) != 0,
        (report[0] & 0x10) != 0,
    ];
    let dx = report[1] as i8 as i16;
    let dy = report[2] as i8 as i16;
    let dz = report[3] as i8;

    Some((dx, dy, dz, buttons))
}
