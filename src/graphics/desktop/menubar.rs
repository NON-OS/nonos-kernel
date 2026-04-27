// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::MENU_BAR_HEIGHT;
use super::menubar_icons::*;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{dimensions, fill_rect, rounded_rect_blend};
use crate::graphics::window::{self, WindowType};
use crate::sys::{clock, serial};

const COLOR_ACCENT: u32 = 0xFF00D4FF;
const COLOR_TEXT: u32 = 0xFFE5E5E5;
const COLOR_TEXT_DIM: u32 = 0xFF9CA3AF;
const MENUBAR_BG: u32 = 0xE8101018;
const PILL_BG: u32 = 0x30FFFFFF;

pub(super) fn draw(w: u32) {
    fill_rect(0, 0, w, MENU_BAR_HEIGHT, MENUBAR_BG);
    fill_rect(0, MENU_BAR_HEIGHT - 1, w, 1, 0x20FFFFFF);
    draw_left_section();
    draw_center_brand(w);
    draw_right_section(w);
}

fn draw_left_section() {
    rounded_rect_blend(12, 6, 80, 22, 6, PILL_BG);
    draw_gear_icon(18, 10);
    draw_text(36, 10, b"Settings", COLOR_TEXT);
}

fn draw_center_brand(w: u32) {
    let brand = b"N\xd8NOS";
    let brand_x = w / 2 - 20;
    draw_text(brand_x, 10, brand, COLOR_ACCENT);
}

fn draw_right_section(w: u32) {
    let mut x = w - 16;
    rounded_rect_blend(x - 28, 6, 32, 22, 11, COLOR_ACCENT);
    draw_text(x - 22, 10, b"U", 0xFF101018);
    x -= 44;
    draw_battery(x - 20, 10);
    x -= 32;
    draw_network_icon(x - 14, 9);
    x -= 26;
    draw_bell_icon(x - 12, 9);
    x -= 24;
    let mut time_buf = [0u8; 8];
    clock::format_time_full(&mut time_buf);
    draw_text(x - 72, 10, &time_buf, COLOR_TEXT);
    x -= 84;
    let mut date_buf = [0u8; 12];
    let date_len = clock::format_date_only(&mut date_buf);
    draw_text(x - (date_len as u32 * 8), 10, &date_buf[..date_len], COLOR_TEXT_DIM);
}

pub(super) fn handle_click(mx: i32, my: i32) -> bool {
    if my < 0 || my >= MENU_BAR_HEIGHT as i32 {
        return false;
    }
    if mx >= 12 && mx < 92 {
        window::open(WindowType::Settings);
        serial::println(b"[UI] Settings clicked");
        return true;
    }
    true
}

pub(super) fn update_clock() {
    super::status::battery::update_battery_status();
    super::status::network::update_network_status();
    let (w, _) = dimensions();
    let x = w - 16 - 44 - 32 - 26 - 24;
    fill_rect(x - 72, 8, 66, 18, MENUBAR_BG);
    let mut time_buf = [0u8; 8];
    clock::format_time_full(&mut time_buf);
    draw_text(x - 72, 10, &time_buf, COLOR_TEXT);
    draw_battery(x - 44 - 32 - 20, 10);
    draw_network_icon(x - 44 - 32 - 26 - 14, 9);
}
