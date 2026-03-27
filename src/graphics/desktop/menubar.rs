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

use crate::graphics::framebuffer::{fill_rect, dimensions, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_text;
use crate::graphics::window::{self, WindowType};
use crate::sys::{serial, clock};
use super::constants::MENU_BAR_HEIGHT;
use super::menubar_icons::*;

const COLOR_ACCENT: u32 = 0xFF00D4FF;
const COLOR_TEXT_SECONDARY: u32 = 0xFFAAAAAA;
const MENUBAR_BG: u32 = 0xF0181820;

pub(super) fn draw(w: u32) {
    // Solid dark background with slight transparency
    fill_rect(0, 0, w, MENU_BAR_HEIGHT, MENUBAR_BG);

    // Subtle top highlight for depth
    fill_rect(0, 0, w, 1, 0x0CFFFFFF);

    // Bottom border - clean single pixel
    fill_rect(0, MENU_BAR_HEIGHT - 1, w, 1, 0x30000000);

    // Left section: Settings button
    let mut x = 16u32;

    draw_gear_icon(x, 10);
    x += 18;

    draw_text(x, 11, b"Settings", COLOR_TEXT_WHITE);

    // Center section: Time | Brand | Date
    let center_x = w / 2;

    let mut time_buf = [0u8; 8];
    clock::format_time_full(&mut time_buf);
    draw_text(center_x - 100, 11, &time_buf[..8], COLOR_TEXT_WHITE);

    // Brand centered
    let brand = b"N\xd8NOS";
    let brand_width = brand.len() as u32 * 8;
    let brand_x = center_x - (brand_width / 2);
    draw_text(brand_x, 11, brand, COLOR_ACCENT);

    let mut date_buf = [0u8; 20];
    let date_len = clock::format_date_short(&mut date_buf);
    draw_text(center_x + 40, 11, &date_buf[..date_len], COLOR_TEXT_SECONDARY);

    // Right section: Status icons
    let mut rx = w - 20;

    draw_avatar(rx - 10, 7);
    rx -= 36;

    draw_battery(rx - 24, 10);
    rx -= 40;

    draw_network_icon(rx - 16, 9);
    rx -= 28;

    draw_bell_icon(rx - 14, 9);
    rx -= 26;

    draw_search_icon(rx - 14, 9);
}

pub(super) fn handle_click(mx: i32, my: i32) -> bool {
    if my < 0 || my >= MENU_BAR_HEIGHT as i32 {
        return false;
    }

    if mx >= 8 && mx < 120 {
        window::open(WindowType::Settings);
        serial::println(b"[UI] Settings clicked");
        return true;
    }

    true
}

pub(super) fn update_clock() {
    let (w, _) = dimensions();
    let center_x = w / 2;

    let mut time_buf = [0u8; 8];
    clock::format_time_full(&mut time_buf);
    let time_x = center_x - 100;

    fill_rect(time_x, 9, 70, 16, MENUBAR_BG);
    draw_text(time_x, 11, &time_buf[..8], COLOR_TEXT_WHITE);
}
