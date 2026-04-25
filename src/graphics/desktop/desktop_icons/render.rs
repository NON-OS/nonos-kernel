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

use super::super::constants::{DOCK_HEIGHT, MENU_BAR_HEIGHT};
use super::state::{
    DesktopIcon, DRAGGING_ICON, ICONS, ICON_COUNT, ICON_POSITIONS, IS_DRAGGING, SELECTED_ICON,
};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::window::draw_string;
use core::sync::atomic::Ordering;

const ICON_SIZE: u32 = 48;
const ICON_SPACING: u32 = 80;
const ICON_START_X: u32 = 140;
const ICON_START_Y: u32 = 60;

pub(super) fn get_icon_position(i: usize, w: u32) -> (u32, u32) {
    unsafe {
        let (px, py) = ICON_POSITIONS[i];
        if px >= 0 && py >= 0 {
            return (px as u32, py as u32);
        }
    }
    let cols = ((w - ICON_START_X - 20) / ICON_SPACING).max(1) as usize;
    let col = i % cols;
    let row = i / cols;
    (
        ICON_START_X + (col as u32) * ICON_SPACING,
        MENU_BAR_HEIGHT + ICON_START_Y + (row as u32) * ICON_SPACING,
    )
}

pub(crate) fn draw(w: u32, h: u32) {
    let cnt = ICON_COUNT.load(Ordering::SeqCst) as usize;
    let sel = SELECTED_ICON.load(Ordering::SeqCst) as usize;
    let dragging_idx = DRAGGING_ICON.load(Ordering::SeqCst) as usize;
    for i in 0..cnt {
        if i == dragging_idx && IS_DRAGGING.load(Ordering::SeqCst) {
            continue;
        }
        let (x, y) = get_icon_position(i, w);
        if y + ICON_SIZE > h - DOCK_HEIGHT {
            continue;
        }
        unsafe {
            draw_icon(x, y, &ICONS[i], i == sel);
        }
    }
    if IS_DRAGGING.load(Ordering::SeqCst) && dragging_idx < cnt {
        let (x, y) = get_icon_position(dragging_idx, w);
        unsafe {
            draw_icon(x, y, &ICONS[dragging_idx], true);
        }
    }
}

fn draw_icon(x: u32, y: u32, icon: &DesktopIcon, selected: bool) {
    if selected {
        fill_rect(x, y - 4, ICON_SIZE, ICON_SIZE + 24, 0x403B82F6);
    }
    let bg = if icon.is_dir { 0xFFFFB800 } else { 0xFFFFFFFF };
    let dark = if icon.is_dir { 0xFFCC9200 } else { 0xFFD0D4DA };
    fill_rect(x + 8, y, ICON_SIZE - 16, ICON_SIZE - 8, bg);
    fill_rect(x + 8, y + ICON_SIZE - 12, ICON_SIZE - 16, 4, dark);
    if icon.is_dir {
        fill_rect(x + 8, y, 16, 8, bg);
        fill_rect(x + 23, y + 3, 4, 4, bg);
    } else {
        for i in 0..5 {
            fill_rect(x + 12, y + 10 + i * 6, 20, 3, 0xFF4D5560);
        }
    }
    let name = &icon.name[..icon.name_len as usize];
    let tx = x + ICON_SIZE / 2 - (name.len() as u32 * 4);
    draw_string(tx, y + ICON_SIZE, name, if selected { 0xFF60A5FA } else { 0xFFFFFFFF });
}
