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

/*
 * Boot Screen Initialization - Cyan neon theme.
 */

use crate::display::background::render_background;
use crate::display::constants::*;
use crate::display::font::{draw_string, CHAR_HEIGHT};
use crate::display::gop::{fill_rect, get_dimensions};

const ASCII_BANNER: &[&[u8]] = &[
    b"",
    b" ##    ## ######  ##    ## ######  ######",
    b" ###   ## ##   ## ###   ## ##   ## ##    ",
    b" ## #  ## ##   ## ## #  ## ##   ## ##### ",
    b" ##  # ## ##   ## ##  # ## ##   ##     ##",
    b" ##   ### ##   ## ##   ### ##   ## ##  ##",
    b" ##    ## ######  ##    ## ######  ##### ",
    b"",
];

pub fn init_boot_screen() {
    render_background();

    let (width, height) = get_dimensions();
    if width == 0 || height == 0 {
        return;
    }

    draw_title_banner(width);
    draw_status_panel(width, height);
}

fn draw_title_banner(width: u32) {
    let banner_x = 40u32;
    let mut banner_y = 40u32;

    for line in ASCII_BANNER {
        draw_string(banner_x, banner_y, line, COLOR_LOGO_PRIMARY);
        banner_y += CHAR_HEIGHT + 2;
    }

    draw_string(banner_x + 4, banner_y + 8, b"ZeroState Bootloader v1.0", COLOR_ACCENT);
    draw_string(banner_x + 4, banner_y + 28, b"Cryptographic Boot Verification", COLOR_TEXT_DIM);

    let sep_y = banner_y + 52;
    fill_rect(banner_x, sep_y, width / 2 - 80, 1, COLOR_ACCENT);
}

fn draw_status_panel(width: u32, height: u32) {
    let panel_w = 420u32;
    let panel_h = 320u32;
    let panel_x = width - panel_w - 40;
    let panel_y = (height - panel_h) / 2;

    fill_rect(panel_x, panel_y, panel_w, 1, COLOR_GLASS_BORDER);
    fill_rect(panel_x, panel_y + panel_h - 1, panel_w, 1, COLOR_GLASS_BORDER);
    fill_rect(panel_x, panel_y, 1, panel_h, COLOR_GLASS_BORDER);
    fill_rect(panel_x + panel_w - 1, panel_y, 1, panel_h, COLOR_GLASS_BORDER);

    draw_string(panel_x + 20, panel_y + 20, b"Boot Verification", COLOR_ACCENT);
    fill_rect(panel_x + 20, panel_y + 40, 180, 1, COLOR_GLASS_BORDER);
}
