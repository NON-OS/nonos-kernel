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

use crate::display::gop::draw_string;


static mut MESSAGES: [&'static str; 10] = [""; 10];
static mut MESSAGE_COUNT: usize = 0;

pub fn draw_boot_messages(x: u32, y: u32) {
    let msg_color = RGB { r: 0x00, g: 0xD4, b: 0x69 };
    let fade_color = RGB { r: 180, g: 180, b: 180 };

    let start_index = if unsafe { MESSAGE_COUNT } > 8 { unsafe { MESSAGE_COUNT } - 8 } else { 0 };

    for i in 0..8 {
        let msg_index = start_index + i;
        if msg_index < unsafe { MESSAGE_COUNT } {
            let message = unsafe { MESSAGES[msg_index % 10] };
            let alpha = if i < 6 { 255 - (6 - i) * 30 } else { 255 };

            let color = if i >= 6 {
                msg_color
            } else {
                RGB {
                    r: (fade_color.r as u16 * alpha / 255) as u8,
                    g: (fade_color.g as u16 * alpha / 255) as u8,
                    b: (fade_color.b as u16 * alpha / 255) as u8,
                }
            };

            draw_string(x, y + i * 18, message, color, 1);
        }
    }
}

pub fn add_boot_message(message: &'static str) {
    unsafe {
        MESSAGES[MESSAGE_COUNT % 10] = message;
        MESSAGE_COUNT += 1;
    }
}