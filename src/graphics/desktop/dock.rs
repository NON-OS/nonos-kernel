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

use super::constants::{DOCK_HEIGHT, DOCK_ICONS, DOCK_ICON_COUNT, DOCK_INNER_HEIGHT, DOCK_WIDTH};
use super::dock_helpers::{draw_icon_plate, draw_rounded_rect};
use super::dock_icons_apps::*;
use super::dock_icons_system::*;
use crate::graphics::framebuffer::{dimensions, fill_rect, put_pixel};
use crate::graphics::window::{self, WindowType};
use crate::sys::serial;

const DOCK_BG: u32 = 0xE0181820;
const PLATE_DARK: u32 = 0xFF1A1E26;
const COLOR_CYAN: u32 = 0xFF22D3EE;

pub(super) fn draw(w: u32, h: u32) {
    let dock_x = (w / 2) - (DOCK_WIDTH / 2);
    let dock_y = h - DOCK_HEIGHT + 6;

    draw_dock_background(dock_x, dock_y);

    let icon_size = 44u32;
    let icon_spacing = 56u32;

    for i in 0..DOCK_ICON_COUNT as u32 {
        let ix = dock_x + 12 + i * icon_spacing;
        let iy = dock_y + 4;
        let wtype = DOCK_ICONS[i as usize];

        draw_app_icon(ix, iy, wtype, icon_size);

        if is_app_running(wtype) {
            let is_min = window::is_window_minimized(wtype);
            draw_active_dot(ix + icon_size / 2, dock_y + DOCK_INNER_HEIGHT - 4, is_min);
        }
    }
}

fn is_app_running(wtype: WindowType) -> bool {
    window::is_window_open(wtype)
}

fn draw_active_dot(cx: u32, y: u32, minimized: bool) {
    let color = if minimized { 0xFF888888 } else { 0xFFFFFFFF };
    for dy in 0..4u32 {
        for dx in 0..4u32 {
            let rel_x = dx as i32 - 2;
            let rel_y = dy as i32 - 2;
            let dist_sq = rel_x * rel_x + rel_y * rel_y;
            if dist_sq <= 3 {
                put_pixel(cx - 2 + dx, y + dy, color);
            }
        }
    }
}

fn draw_dock_background(x: u32, y: u32) {
    let w = DOCK_WIDTH;
    let h = DOCK_INNER_HEIGHT;
    let radius = 16u32;

    for layer in 0..4u32 {
        let alpha = (16 - layer * 4) as u32;
        let offset = layer + 2;
        draw_rounded_rect_shadow(x + 1, y + offset, w, h, radius, alpha << 24);
    }

    draw_rounded_rect(x, y, w, h, radius, DOCK_BG);
    fill_rect(x + radius, y, w - radius * 2, 1, 0x0AFFFFFF);
    fill_rect(x + radius, y + h - 1, w - radius * 2, 1, 0x10000000);
}

fn draw_rounded_rect_shadow(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - r * 2, h, color);
    fill_rect(x, y + r, w, h - r * 2, color);
}

fn draw_app_icon(x: u32, y: u32, app: WindowType, size: u32) {
    match app {
        WindowType::Terminal => draw_terminal_icon(x, y, size),
        WindowType::FileManager => draw_folder_icon(x, y, size),
        WindowType::TextEditor => draw_document_icon(x, y, size),
        WindowType::Calculator => draw_calculator_icon(x, y, size),
        WindowType::Wallet => draw_wallet_icon(x, y, size),
        WindowType::Marketplace => draw_marketplace_icon(x, y, size),
        WindowType::Agents => draw_agents_icon(x, y, size),
        WindowType::ProcessManager => draw_monitor_icon(x, y, size),
        WindowType::Settings => draw_gear_icon(x, y, size),
        WindowType::Browser => draw_globe_icon(x, y, size),
        WindowType::About => draw_info_icon(x, y, size),
        _ => {
            draw_icon_plate(x, y, size, PLATE_DARK);
            fill_rect(x + size / 4, y + size / 4, size / 2, size / 2, COLOR_CYAN);
        }
    }
}

pub(super) fn handle_click(mx: i32, my: i32) -> bool {
    let (w, h) = dimensions();

    let dock_x = (w / 2) - (DOCK_WIDTH / 2);
    let dock_y = h - DOCK_HEIGHT + 6;

    if mx < dock_x as i32 || mx >= (dock_x + DOCK_WIDTH) as i32 {
        return false;
    }
    if my < dock_y as i32 || my >= (dock_y + DOCK_INNER_HEIGHT) as i32 {
        return false;
    }

    let rel_x = mx as u32 - dock_x;
    let icon_size = 44u32;
    let icon_spacing = 56u32;

    for i in 0..DOCK_ICON_COUNT as u32 {
        let icon_x = 12 + i * icon_spacing;
        if rel_x >= icon_x && rel_x < icon_x + icon_size {
            let wtype = DOCK_ICONS[i as usize];
            if wtype != WindowType::None {
                if window::is_window_minimized(wtype) {
                    window::restore(wtype);
                    serial::println(b"[UI] Restored app from dock");
                } else {
                    window::open(wtype);
                    serial::println(b"[UI] Opened app from dock");
                }
                return true;
            }
        }
    }

    false
}
