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
use super::frame::TerminalLayout;

const TITLE: &[u8] = b"NONOS BOOT CONSOLE";
const COLOR_TITLE: u32 = 0x66FFFF;
const COLOR_LOGO: u32 = 0x66FFFF;

const ASCII_BANNER: &[&[u8]] = &[
    b" ##    ## ######  ##    ## ######  ######",
    b" ###   ## ##   ## ###   ## ##   ## ##    ",
    b" ## #  ## ##   ## ## #  ## ##   ## ##### ",
    b" ##  # ## ##   ## ##  # ## ##   ##     ##",
    b" ##   ### ##   ## ##   ### ##   ## ##  ##",
    b" ##    ## ######  ##    ## ######  ##### ",
];

pub fn draw_terminal_header(layout: &TerminalLayout) {
    draw_string(layout.x + 16, layout.y + 10, TITLE, COLOR_TITLE);
    draw_dots(layout);
}

pub fn draw_ascii_banner(layout: &TerminalLayout) {
    let banner_x = layout.content_x;
    let mut y = layout.content_y;

    for line in ASCII_BANNER {
        draw_string(banner_x, y, line, COLOR_LOGO);
        y += 12;
    }

    let sub_y = y + 8;
    draw_string(banner_x, sub_y, b"ZeroState Bootloader v1.0", 0x66FFFF);
    draw_string(banner_x, sub_y + 18, b"Cryptographic Boot Verification", 0x707080);
}

fn draw_dots(layout: &TerminalLayout) {
    let dot_y = layout.y + 12;
    let base_x = layout.x + layout.width - 60;

    draw_dot(base_x, dot_y, 0x66FFFF);
    draw_dot(base_x + 16, dot_y, 0x33CCCC);
    draw_dot(base_x + 32, dot_y, 0x2E5C5C);
}

fn draw_dot(cx: u32, cy: u32, color: u32) {
    let r = 4u32;
    for dy in 0..=r {
        for dx in 0..=r {
            let dist_sq = dx * dx + dy * dy;
            if dist_sq <= r * r {
                crate::display::gop::put_pixel(cx + dx, cy + dy, color);
                if dx > 0 {
                    crate::display::gop::put_pixel(cx - dx, cy + dy, color);
                }
                if dy > 0 {
                    crate::display::gop::put_pixel(cx + dx, cy - dy, color);
                }
                if dx > 0 && dy > 0 {
                    crate::display::gop::put_pixel(cx - dx, cy - dy, color);
                }
            }
        }
    }
}
