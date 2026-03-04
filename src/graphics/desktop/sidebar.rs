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

use crate::graphics::framebuffer::{fill_rect, put_pixel};
use super::constants::{MENU_BAR_HEIGHT, SIDEBAR_WIDTH};
use super::sidebar_icons::{draw_terminal_icon, draw_folder_icon, draw_browser_icon, draw_wallet_icon};
use super::sidebar_utils::draw_info_icon;

const GLASS_BG: u32 = 0xF0080A0C;
const GLASS_EDGE_DARK: u32 = 0x18000000;

pub(super) fn draw(h: u32) {
    let sidebar_h = h - MENU_BAR_HEIGHT;

    fill_rect(0, MENU_BAR_HEIGHT, SIDEBAR_WIDTH, sidebar_h, GLASS_BG);

    for y in 0..40u32 {
        let alpha = ((40 - y) * 3 / 4) as u32;
        if alpha > 0 {
            let color = (alpha << 24) | 0x1A1E24;
            fill_rect(1, MENU_BAR_HEIGHT + y, SIDEBAR_WIDTH - 2, 1, color);
        }
    }

    for y in 0..sidebar_h {
        let fade = if y < 100 {
            8
        } else if y > sidebar_h - 100 {
            8 - ((y - (sidebar_h - 100)) * 8 / 100).min(8) as u32
        } else {
            8
        };
        if fade > 0 {
            put_pixel(0, MENU_BAR_HEIGHT + y, (fade << 24) | 0xFFFFFF);
        }
    }

    for y in 0..sidebar_h {
        put_pixel(SIDEBAR_WIDTH - 1, MENU_BAR_HEIGHT + y, GLASS_EDGE_DARK);
    }

    let icons_start = MENU_BAR_HEIGHT + 24;
    let icon_spacing = 56u32;
    let cx = SIDEBAR_WIDTH / 2;

    draw_terminal_icon(cx, icons_start);
    draw_folder_icon(cx, icons_start + icon_spacing);
    draw_browser_icon(cx, icons_start + icon_spacing * 2);
    draw_wallet_icon(cx, icons_start + icon_spacing * 3);

    let bottom_y = MENU_BAR_HEIGHT + sidebar_h - 70;

    for x in 12..SIDEBAR_WIDTH - 12 {
        let dist_from_center = ((x as i32 - SIDEBAR_WIDTH as i32 / 2).abs()) as u32;
        let alpha = (12u32.saturating_sub(dist_from_center / 2)).min(12);
        put_pixel(x, bottom_y, (alpha << 24) | 0xFFFFFF);
    }

    draw_info_icon(cx, bottom_y + 20);
}

pub(super) fn handle_click(mx: i32, my: i32) -> bool {
    use crate::graphics::window::{self, WindowType};
    use crate::graphics::framebuffer::dimensions;

    if mx < 0 || mx >= SIDEBAR_WIDTH as i32 {
        return false;
    }
    if my < MENU_BAR_HEIGHT as i32 {
        return false;
    }

    let (_, h) = dimensions();
    let sidebar_h = h - MENU_BAR_HEIGHT;

    let icons_start = MENU_BAR_HEIGHT + 24;
    let icon_spacing = 56u32;
    let icon_size = 40u32;

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
            window::open(wtype);
            return true;
        }
    }

    let bottom_y = MENU_BAR_HEIGHT + sidebar_h - 70;
    let info_y = bottom_y + 20;
    if rel_y >= info_y - icon_size / 2 && rel_y < info_y + icon_size / 2 {
        window::open(WindowType::About);
        return true;
    }

    false
}
