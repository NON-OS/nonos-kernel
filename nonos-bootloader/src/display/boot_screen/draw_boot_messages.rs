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

use crate::display::font::draw_string;

static mut MESSAGES: [&'static str; 10] = [""; 10];
static mut MESSAGE_COUNT: usize = 0;

pub fn draw_boot_messages(x: u32, y: u32) {
    let msg_color = 0xFF00D469u32;
    let fade_color = 0xFFB4B4B4u32;

    let start_index = if unsafe { MESSAGE_COUNT } > 8 {
        unsafe { MESSAGE_COUNT } - 8
    } else {
        0usize
    };

    for i in 0..8 {
        let msg_index = start_index + i;
        if msg_index < unsafe { MESSAGE_COUNT } {
            let message = unsafe { MESSAGES[msg_index % 10] };
            let alpha = if i < 6 { 255u32 - (6 - i) as u32 * 30 } else { 255u32 };

            let color = if i >= 6 {
                msg_color
            } else {
                let fade_r = (fade_color >> 16) & 0xFF;
                let fade_g = (fade_color >> 8) & 0xFF;
                let fade_b = fade_color & 0xFF;

                let r = (fade_r * alpha / 255) & 0xFF;
                let g = (fade_g * alpha / 255) & 0xFF;
                let b = (fade_b * alpha / 255) & 0xFF;

                0xFF000000 | (r << 16) | (g << 8) | b
            };

            draw_string(x, y + (i as u32) * 18, message.as_bytes(), color);
        }
    }
}

pub fn add_boot_message(message: &'static str) {
    unsafe {
        MESSAGES[MESSAGE_COUNT % 10] = message;
        MESSAGE_COUNT += 1;
    }
}