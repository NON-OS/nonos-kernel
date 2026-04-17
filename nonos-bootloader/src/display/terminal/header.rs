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

const COLOR_ACCENT: u32 = 0xFF00D4AA;
const COLOR_DIM: u32 = 0xFF0A2828;
const COLOR_TEXT: u32 = 0xFF556677;

const ASCII_LOGO: [&[u8]; 6] = [
    b" ##    ##  #####  ##    ##  #####   ##### ",
    b" ###   ## ##   ## ###   ## ##   ## ##     ",
    b" ## #  ## ##   ## ## #  ## ##   ##  ##### ",
    b" ##  # ## ##   ## ##  # ## ##   ##      ##",
    b" ##   ### ##   ## ##   ### ##   ## ##   ##",
    b" ##    ##  #####  ##    ##  #####   ##### ",
];

pub fn draw_terminal_header(_layout: &TerminalLayout) {}

pub fn draw_ascii_banner(layout: &TerminalLayout) {
    let x = layout.x + 24;
    let mut y = layout.y + 16;

    for line in ASCII_LOGO.iter() {
        draw_string(x, y, *line, COLOR_ACCENT);
        y += 14;
    }

    fill_rect(x, y + 6, 340, 1, COLOR_DIM);
    draw_string(x, y + 14, b"SOVEREIGNTY FROM ZERO", COLOR_TEXT);
}
