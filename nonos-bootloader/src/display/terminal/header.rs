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
use crate::display::gop::fill_rect;
use super::frame::TerminalLayout;

const COLOR_CYAN: u32 = 0xFF66FFFF;
const COLOR_DIM: u32 = 0xFF2E5C5C;
const COLOR_TEXT: u32 = 0xFF6B7280;

const ASCII_LOGO: &[&[u8]] = &[
    b" ##    ##  #####  ##    ##  #####   ##### ",
    b" ###   ## ##   ## ###   ## ##   ## ##     ",
    b" ## #  ## ##   ## ## #  ## ##   ##  ##### ",
    b" ##  # ## ##   ## ##  # ## ##   ##      ##",
    b" ##   ### ##   ## ##   ### ##   ## ##   ##",
    b" ##    ##  #####  ##    ##  #####   ##### ",
];

pub fn draw_terminal_header(_layout: &TerminalLayout) {}

pub fn draw_ascii_banner(layout: &TerminalLayout) {
    let x = layout.x + 20;
    let mut y = layout.y + 10;
    for line in ASCII_LOGO {
        draw_string(x, y, line, COLOR_CYAN);
        y += 12;
    }
    fill_rect(x, y + 4, 340, 1, COLOR_DIM);
    draw_string(x, y + 10, b"SOVEREIGNTY FROM ZERO", COLOR_TEXT);
    draw_dots(layout);
}

fn draw_dots(layout: &TerminalLayout) {
    let y = layout.y + 35;
    let x = layout.x + layout.width - 80;
    draw_dot(x, y, COLOR_CYAN);
    draw_dot(x + 20, y, COLOR_DIM);
    draw_dot(x + 40, y, 0xFF1A3030);
}

fn draw_dot(cx: u32, cy: u32, color: u32) {
    for dy in 0..6u32 {
        for dx in 0..6u32 {
            if (dx as i32 - 3).pow(2) + (dy as i32 - 3).pow(2) <= 9 {
                crate::display::gop::put_pixel(cx + dx, cy + dy, color);
            }
        }
    }
}
