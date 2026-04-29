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

use super::items::*;
use super::state::{get_active_menu, set_active_menu, MenuId};
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

const MENU_BG: u32 = 0xF0181820;
const MENU_HOVER: u32 = 0xFF2A2A38;
const MENU_BORDER: u32 = 0xFF303040;
const TEXT_PRIMARY: u32 = 0xFFE5E5E7;
const TEXT_DIM: u32 = 0xFF8888A0;
const ITEM_HEIGHT: u32 = 28;
const MENU_PADDING: u32 = 8;

pub(super) fn is_dropdown_open() -> bool {
    get_active_menu() != MenuId::None
}

pub(super) fn close_dropdown() {
    set_active_menu(MenuId::None);
}

pub(super) fn draw_dropdown(x: u32, y: u32, menu: MenuId) {
    let items = menu_items(menu);
    if items.is_empty() {
        return;
    }
    let h = items.len() as u32 * ITEM_HEIGHT + MENU_PADDING * 2 + separator_count(items) * 8;
    let w = menu_width(items);
    fill_rounded_rect(x, y, w, h, 8, MENU_BG);
    fill_rect(x, y, w, 1, MENU_BORDER);
    fill_rect(x, y + h - 1, w, 1, MENU_BORDER);
    fill_rect(x, y, 1, h, MENU_BORDER);
    fill_rect(x + w - 1, y, 1, h, MENU_BORDER);
    let mut item_y = y + MENU_PADDING;
    for item in items {
        draw_item(x + MENU_PADDING, item_y, w - MENU_PADDING * 2, item);
        item_y += ITEM_HEIGHT;
        if item.separator_after {
            fill_rect(x + MENU_PADDING, item_y, w - MENU_PADDING * 2, 1, MENU_BORDER);
            item_y += 8;
        }
    }
}

fn draw_item(x: u32, y: u32, w: u32, item: &MenuItem) {
    let text_color = if item.enabled { TEXT_PRIMARY } else { TEXT_DIM };
    draw_text(x + 8, y + 8, item.label, text_color);
    if let Some(shortcut) = item.shortcut {
        let sx = x + w - shortcut.len() as u32 * 8 - 8;
        draw_text(sx, y + 8, shortcut, TEXT_DIM);
    }
}

fn menu_items(menu: MenuId) -> &'static [MenuItem] {
    match menu {
        MenuId::File => FILE_MENU,
        MenuId::Edit => EDIT_MENU,
        MenuId::View => VIEW_MENU,
        MenuId::Window => WINDOW_MENU,
        MenuId::Help => HELP_MENU,
        _ => &[],
    }
}

fn menu_width(items: &[MenuItem]) -> u32 {
    let max_label = items.iter().map(|i| i.label.len()).max().unwrap_or(0);
    let max_shortcut = items.iter().filter_map(|i| i.shortcut).map(|s| s.len()).max().unwrap_or(0);
    ((max_label + max_shortcut) as u32 * 8 + 48).max(180)
}

fn separator_count(items: &[MenuItem]) -> u32 {
    items.iter().filter(|i| i.separator_after).count() as u32
}
