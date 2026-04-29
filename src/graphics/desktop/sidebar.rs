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
use super::sidebar_icons::{draw_browser_icon, draw_folder_icon, draw_terminal_icon, draw_wallet_icon};
use super::sidebar_utils::draw_info_icon;
use crate::graphics::framebuffer::{fill_rect, put_pixel, rounded_rect_blend};
use crate::graphics::window::{self, WindowType};

const GLASS_BG: u32 = 0xF0080A0C;
const ICON_BG: u32 = 0x20FFFFFF;
const ICON_BG_ACTIVE: u32 = 0x40FFFFFF;

pub(super) fn draw(h: u32) {
    let sidebar_h = h - MENU_BAR_HEIGHT;
    fill_rect(0, MENU_BAR_HEIGHT, SIDEBAR_WIDTH, sidebar_h, GLASS_BG);
    for y in 0..sidebar_h {
        put_pixel(SIDEBAR_WIDTH - 1, MENU_BAR_HEIGHT + y, 0x10000000);
    }
    draw_app_icons(sidebar_h);
    draw_bottom_section(sidebar_h);
}

fn draw_app_icons(_sidebar_h: u32) {
    let start = MENU_BAR_HEIGHT + 28;
    let spacing = 58u32;
    let cx = SIDEBAR_WIDTH / 2;
    let types = [WindowType::Terminal, WindowType::FileManager, WindowType::Browser, WindowType::Wallet];
    let draw_fns: [fn(u32, u32); 4] = [draw_terminal_icon, draw_folder_icon, draw_browser_icon, draw_wallet_icon];
    for (i, (&wtype, draw_fn)) in types.iter().zip(draw_fns.iter()).enumerate() {
        let y = start + spacing * i as u32;
        let bg = if window::is_window_open(wtype) { ICON_BG_ACTIVE } else { ICON_BG };
        rounded_rect_blend(cx - 22, y - 22, 44, 44, 12, bg);
        draw_fn(cx, y);
    }
}

fn draw_bottom_section(sidebar_h: u32) {
    let y = MENU_BAR_HEIGHT + sidebar_h - 70;
    let cx = SIDEBAR_WIDTH / 2;
    for x in 14..SIDEBAR_WIDTH - 14 {
        let dist = ((x as i32 - cx as i32).abs()) as u32;
        let alpha = 10u32.saturating_sub(dist / 3);
        if alpha > 0 { put_pixel(x, y, (alpha << 24) | 0xFFFFFF); }
    }
    let bg = if window::is_window_open(WindowType::About) { ICON_BG_ACTIVE } else { ICON_BG };
    rounded_rect_blend(cx - 22, y + 18, 44, 44, 12, bg);
    draw_info_icon(cx, y + 40);
}

pub(super) fn handle_click(mx: i32, my: i32) -> bool {
    use crate::graphics::framebuffer::dimensions;
    if mx < 0 || mx >= SIDEBAR_WIDTH as i32 || my < MENU_BAR_HEIGHT as i32 { return false; }
    let (_, h) = dimensions();
    let sidebar_h = h - MENU_BAR_HEIGHT;
    let start = MENU_BAR_HEIGHT + 28;
    let spacing = 58u32;
    let types = [WindowType::Terminal, WindowType::FileManager, WindowType::Browser, WindowType::Wallet];
    for (i, &wtype) in types.iter().enumerate() {
        let icon_y = start + spacing * i as u32;
        if (my as u32) >= icon_y - 22 && (my as u32) < icon_y + 22 {
            if window::is_window_minimized(wtype) { window::restore(wtype); }
            else { window::open(wtype); }
            return true;
        }
    }
    let bottom_y = MENU_BAR_HEIGHT + sidebar_h - 70;
    if (my as u32) >= bottom_y + 18 && (my as u32) < bottom_y + 62 {
        if window::is_window_minimized(WindowType::About) { window::restore(WindowType::About); }
        else { window::open(WindowType::About); }
        return true;
    }
    false
}
