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

use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::window::settings::render::{draw_string, draw_toggle};
use crate::graphics::window::settings::state::*;

pub(crate) fn draw(x: u32, y: u32, w: u32) {
    draw_string(x + 15, y, b"Privacy Mode", COLOR_TEXT_WHITE);
    draw_string(x + 15, y + 18, b"Controls network privacy level", 0xFF7D8590);

    let modes: [&[u8]; 4] = [b"Standard", b"Anonymous", b"Maximum", b"Isolated"];
    let current_mode = get_privacy_mode();
    let btn_w = 75u32;

    for (i, name) in modes.iter().enumerate() {
        let bx = x + 15 + (i as u32) * (btn_w + 8);
        let by = y + 40;
        let is_sel = current_mode == i as u8;
        let color = if is_sel { COLOR_ACCENT } else { 0xFF2D333B };
        fill_rect(bx, by, btn_w, 28, color);
        let txt = if is_sel { 0xFF0D1117 } else { COLOR_TEXT_WHITE };
        draw_string(bx + 4, by + 6, name, txt);
    }

    draw_string(x + 15, y + 85, b"NYM Mixnet", COLOR_TEXT_WHITE);
    draw_toggle(x + w - 70, y + 80, is_anyone_enabled());

    if is_anyone_enabled() {
        draw_string(x + 15, y + 108, b"All traffic via NYM Mixnet", COLOR_GREEN);
    } else {
        draw_string(x + 15, y + 108, b"Direct connections (no anonymity)", 0xFFFF6B6B);
    }

    draw_string(x + 15, y + 140, b"MAC Randomization", COLOR_TEXT_WHITE);
    draw_toggle(x + w - 70, y + 135, is_privacy_enabled());

    draw_string(x + 15, y + 180, b"ZeroState Mode", COLOR_TEXT_WHITE);
    draw_string(x + 15, y + 198, b"RAM-only, no disk persistence", 0xFF7D8590);
    draw_toggle(x + w - 70, y + 175, is_zero_state_enabled());
}
