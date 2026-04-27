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

use super::constants::{MENU_BAR_HEIGHT, SIDEBAR_WIDTH};
use super::sidebar_icons::{
    draw_browser_icon, draw_folder_icon, draw_terminal_icon, draw_wallet_icon,
};
use super::sidebar_utils::draw_info_icon;
use crate::graphics::framebuffer::{fill_rect, put_pixel, rounded_rect_blend};

const GLASS_BG: u32 = 0xF0080A0C;
const ICON_BG: u32 = 0x20FFFFFF;

pub(super) fn draw(h: u32) {
    let sidebar_h = h - MENU_BAR_HEIGHT;
    fill_rect(0, MENU_BAR_HEIGHT, SIDEBAR_WIDTH, sidebar_h, GLASS_BG);
    draw_edge_highlights(sidebar_h);
    draw_app_icons(sidebar_h);
    draw_bottom_section(sidebar_h);
}

fn draw_edge_highlights(sidebar_h: u32) {
    for y in 0..sidebar_h {
        put_pixel(SIDEBAR_WIDTH - 1, MENU_BAR_HEIGHT + y, 0x10000000);
        if y < 60 {
            let alpha = ((60 - y) / 6) as u32;
            put_pixel(1, MENU_BAR_HEIGHT + y, (alpha << 24) | 0xFFFFFF);
        }
    }
}

fn draw_app_icons(_sidebar_h: u32) {
    let icons_start = MENU_BAR_HEIGHT + 28;
    let icon_spacing = 58u32;
    let cx = SIDEBAR_WIDTH / 2;
    let icon_data: [(fn(u32, u32), u32); 4] = [
        (draw_terminal_icon, 0xFF10B981),
        (draw_folder_icon, 0xFFFBBF24),
        (draw_browser_icon, 0xFF3B82F6),
        (draw_wallet_icon, 0xFF8B5CF6),
    ];
    for (i, (draw_fn, _color)) in icon_data.iter().enumerate() {
        let y = icons_start + icon_spacing * i as u32;
        rounded_rect_blend(cx - 22, y - 22, 44, 44, 12, ICON_BG);
        draw_fn(cx, y);
    }
}

fn draw_bottom_section(sidebar_h: u32) {
    let bottom_y = MENU_BAR_HEIGHT + sidebar_h - 70;
    let cx = SIDEBAR_WIDTH / 2;
    for x in 14..SIDEBAR_WIDTH - 14 {
        let dist = ((x as i32 - cx as i32).abs()) as u32;
        let alpha = 10u32.saturating_sub(dist / 3);
        if alpha > 0 {
            put_pixel(x, bottom_y, (alpha << 24) | 0xFFFFFF);
        }
    }
    rounded_rect_blend(cx - 22, bottom_y + 18, 44, 44, 12, ICON_BG);
    draw_info_icon(cx, bottom_y + 40);
}

pub(super) fn handle_click(mx: i32, my: i32) -> bool {
    use crate::graphics::framebuffer::dimensions;
    use crate::graphics::window::{self, WindowType};
    if mx < 0 || mx >= SIDEBAR_WIDTH as i32 || my < MENU_BAR_HEIGHT as i32 {
        return false;
    }
    let (_, h) = dimensions();
    let sidebar_h = h - MENU_BAR_HEIGHT;
    let icons_start = MENU_BAR_HEIGHT + 28;
    let icon_spacing = 58u32;
    let icon_size = 44u32;
    let rel_y = my as u32;
    for i in 0..4u32 {
        let icon_y = icons_start + icon_spacing * i;
        if rel_y >= icon_y - icon_size / 2 && rel_y < icon_y + icon_size / 2 {
            let wtype = match i {
                0 => WindowType::Terminal,
                1 => WindowType::FileManager,
                2 => WindowType::Browser,
                3 => WindowType::Wallet,
                _ => return false,
            };
            if window::is_window_minimized(wtype) {
                window::restore(wtype);
            } else {
                window::open(wtype);
            }
            return true;
        }
    }
    let bottom_y = MENU_BAR_HEIGHT + sidebar_h - 70;
    if rel_y >= bottom_y + 18 && rel_y < bottom_y + 62 {
        if window::is_window_minimized(WindowType::About) {
            window::restore(WindowType::About);
        } else {
            window::open(WindowType::About);
        }
        return true;
    }
    false
}
