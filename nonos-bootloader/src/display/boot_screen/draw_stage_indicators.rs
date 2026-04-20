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

use crate::display::gop::fill_rect;

static mut CURRENT_STAGE: u8 = 0;

pub fn draw_stage_indicators(x: u32, y: u32) {
    let complete_color = 0xFF4CAF50u32;
    let current_color = 0xFFFFD700u32;
    let pending_color = 0xFF3C3C3Cu32;

    for stage in 0u32..10u32 {
        let indicator_y = y + stage * 12;
        let indicator_size = 8;

        let color = if stage < unsafe { CURRENT_STAGE } as u32 {
            complete_color
        } else if stage == unsafe { CURRENT_STAGE } as u32 {
            current_color
        } else {
            pending_color
        };

        fill_rect(x, indicator_y, indicator_size, indicator_size, color);

        if stage == unsafe { CURRENT_STAGE } as u32 {
            let pulse_size = indicator_size + 2;
            let pulse_color = ((color & 0xFF000000) | ((color & 0x00FEFEFE) >> 1)) as u32;
            fill_rect(x - 1, indicator_y - 1, pulse_size, pulse_size, pulse_color);
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