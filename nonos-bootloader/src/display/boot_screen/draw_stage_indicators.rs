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

use crate::graphics::framebuffer::draw_filled_rect;
use crate::graphics::colors::RGB;

static mut CURRENT_STAGE: u8 = 0;

pub fn draw_stage_indicators(x: u32, y: u32) {
    let complete_color = RGB { r: 0x4C, g: 0xAF, b: 0x50 };
    let current_color = RGB { r: 0xFF, g: 0xD7, b: 0x00 };
    let pending_color = RGB { r: 60, g: 60, b: 60 };

    for stage in 0..10 {
        let indicator_y = y + stage * 12;
        let indicator_size = 8;

        let color = if stage < unsafe { CURRENT_STAGE } {
            complete_color
        } else if stage == unsafe { CURRENT_STAGE } {
            current_color
        } else {
            pending_color
        };

        draw_filled_rect(x, indicator_y, indicator_size, indicator_size, color);

        if stage == unsafe { CURRENT_STAGE } {
            let pulse_size = indicator_size + 2;
            let pulse_color = RGB { r: color.r / 2, g: color.g / 2, b: color.b / 2 };
            draw_filled_rect(x - 1, indicator_y - 1, pulse_size, pulse_size, pulse_color);
        }
    }
}

pub fn set_current_stage(stage: u8) {
    unsafe { CURRENT_STAGE = stage; }
}

pub fn advance_stage() {
    unsafe {
        if CURRENT_STAGE < 10 {
            CURRENT_STAGE += 1;
        }
    }
}