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

use super::magnify::{get_icon_y_offset, get_magnified_size};
use crate::graphics::desktop::constants::{DOCK_HEIGHT, DOCK_ICONS, DOCK_ICON_COUNT, DOCK_INNER_HEIGHT, DOCK_WIDTH};
use crate::graphics::desktop::dock_helpers::draw_rounded_rect;
use crate::graphics::framebuffer::{dimensions, fill_rect, put_pixel};
use crate::graphics::window::{self, WindowType};

const DOCK_BG: u32 = 0xE8101018;
const ICON_SPACING: u32 = 58;
const BASE_ICON_SIZE: u32 = 44;

pub fn draw(w: u32, h: u32) {
    let dock_x = (w / 2) - (DOCK_WIDTH / 2);
    let dock_y = h - DOCK_HEIGHT + 4;
    draw_dock_bg(dock_x, dock_y);
    for i in 0..DOCK_ICON_COUNT as u32 {
        let size = get_magnified_size(i, dock_x);
        let y_off = get_icon_y_offset(size);
        let ix = dock_x + 14 + i * ICON_SPACING + (BASE_ICON_SIZE - size) / 2;
        let iy = (dock_y as i32 + 6 + y_off) as u32;
        let wtype = DOCK_ICONS[i as usize];
        draw_icon(ix, iy, wtype, size);
        if window::is_window_open(wtype) {
            let minimized = window::is_window_minimized(wtype);
            draw_indicator(ix + size / 2, dock_y + DOCK_INNER_HEIGHT - 5, minimized);
        }
    }
}

fn draw_icon(x: u32, y: u32, wtype: WindowType, size: u32) {
    use crate::graphics::desktop::dock_icons_apps::*;
    match wtype {
        WindowType::Terminal => draw_terminal_icon(x, y, size),
        WindowType::FileManager => draw_folder_icon(x, y, size),
        WindowType::TextEditor => draw_document_icon(x, y, size),
        WindowType::Calculator => draw_calculator_icon(x, y, size),
        WindowType::Wallet => draw_wallet_icon(x, y, size),
        WindowType::Marketplace => draw_marketplace_icon(x, y, size),
        WindowType::Agents => draw_agents_icon(x, y, size),
        WindowType::ProcessManager => draw_process_manager_icon(x, y, size),
        WindowType::Settings => draw_settings_icon(x, y, size),
        WindowType::Browser => draw_browser_icon(x, y, size),
        WindowType::About => draw_about_icon(x, y, size),
        _ => {}
    }
}

fn draw_dock_bg(x: u32, y: u32) {
    draw_rounded_rect(x, y, DOCK_WIDTH, DOCK_INNER_HEIGHT, 18, DOCK_BG);
    fill_rect(x + 18, y, DOCK_WIDTH - 36, 1, 0x08FFFFFF);
}

fn draw_indicator(cx: u32, y: u32, minimized: bool) {
    let color = if minimized { 0xFF666666 } else { 0xFFFFFFFF };
    for dy in 0..3u32 {
        for dx in 0..3u32 {
            let rx = dx as i32 - 1;
            let ry = dy as i32 - 1;
            if rx * rx + ry * ry <= 1 { put_pixel(cx - 1 + dx, y + dy, color); }
        }
    }
}

pub fn handle_click(mx: i32, my: i32) -> bool {
    let (w, h) = dimensions();
    let dock_x = (w / 2) - (DOCK_WIDTH / 2);
    let dock_y = h - DOCK_HEIGHT + 4;
    if mx < dock_x as i32 || mx >= (dock_x + DOCK_WIDTH) as i32 { return false; }
    if my < dock_y as i32 || my >= (dock_y + DOCK_INNER_HEIGHT) as i32 { return false; }
    let rel_x = mx as u32 - dock_x;
    for i in 0..DOCK_ICON_COUNT as u32 {
        let icon_x = 14 + i * ICON_SPACING;
        if rel_x >= icon_x && rel_x < icon_x + BASE_ICON_SIZE {
            let wtype = DOCK_ICONS[i as usize];
            if wtype != WindowType::None {
                if window::is_window_minimized(wtype) { window::restore(wtype); }
                else { window::open(wtype); }
                return true;
            }
        }
    }
    false
}
