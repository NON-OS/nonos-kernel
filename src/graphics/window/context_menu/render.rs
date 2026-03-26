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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::design_system::colors::*;
use crate::graphics::components::{primitives, text};
use super::types::{ContextMenuType, MenuItemType};
use super::state::*;
use super::menus::get_items;

const MENU_CORNER_RADIUS: u32 = 10;

pub fn draw() {
    if !is_visible() { return; }

    let x = MENU_X.load(Ordering::Relaxed) as u32;
    let y = MENU_Y.load(Ordering::Relaxed) as u32;
    let w = MENU_WIDTH.load(Ordering::Relaxed) as u32;
    let h = MENU_HEIGHT.load(Ordering::Relaxed) as u32;
    let hover_idx = MENU_HOVER_INDEX.load(Ordering::Relaxed);

    let menu_type = match MENU_TYPE.load(Ordering::Relaxed) {
        1 => ContextMenuType::Desktop,
        2 => ContextMenuType::FileManager,
        3 => ContextMenuType::TextEditor,
        4 => ContextMenuType::Window,
        _ => return,
    };

    draw_shadow(x, y, w, h);
    primitives::rounded_rect(x, y, w, h, MENU_CORNER_RADIUS, 0xF01C1C1E);
    draw_highlight(x, y, w);
    draw_items(x, y, w, hover_idx, get_items(menu_type));
}

fn draw_shadow(x: u32, y: u32, w: u32, h: u32) {
    for shadow in 0..6u32 {
        let alpha = 25 - shadow * 4;
        primitives::rounded_rect(x + shadow / 2, y + shadow + 2, w, h, MENU_CORNER_RADIUS, alpha << 24);
    }
}

fn draw_highlight(x: u32, y: u32, w: u32) {
    for gy in 0..MENU_CORNER_RADIUS {
        let alpha = 8 - (gy / 2).min(8);
        fill_rect(x + MENU_CORNER_RADIUS, y + gy, w - 2 * MENU_CORNER_RADIUS, 1, (alpha << 24) | 0xFFFFFF);
    }
}

fn draw_items(x: u32, y: u32, w: u32, hover_idx: i32, items: &[super::types::MenuItem]) {
    let mut item_y = y + MENU_PADDING;
    for (i, item) in items.iter().enumerate() {
        if item.item_type == MenuItemType::Separator {
            fill_rect(x + 12, item_y + 4, w - 24, 1, BORDER_DEFAULT);
            item_y += 9;
        } else {
            if hover_idx == i as i32 && item.item_type == MenuItemType::Action {
                primitives::rounded_rect(x + 6, item_y + 2, w - 12, MENU_ITEM_HEIGHT - 4, 6, ACCENT);
            }
            let text_color = if item.item_type == MenuItemType::Disabled { TEXT_SECONDARY } else { TEXT_PRIMARY };
            text::draw(x + 16, item_y + (MENU_ITEM_HEIGHT - 16) / 2, item.label, text_color);
            item_y += MENU_ITEM_HEIGHT;
        }
    }
}
