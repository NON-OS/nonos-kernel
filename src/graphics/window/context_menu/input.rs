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

use super::menus::get_items;
use super::state::*;
use super::types::{ContextMenuType, MenuItemType};
use core::sync::atomic::Ordering;

pub fn update_hover(mx: i32, my: i32) {
    if !is_visible() {
        return;
    }
    let (x, y, w, h) = get_bounds();
    if mx < x || mx >= x + w || my < y || my >= y + h {
        MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
        return;
    }
    if let Some(menu_type) = get_type() {
        find_hover_item(my, y, get_items(menu_type));
    }
}

pub fn handle_click(mx: i32, my: i32) -> Option<u8> {
    if !is_visible() {
        return None;
    }
    let (x, y, w, h) = get_bounds();
    if mx < x || mx >= x + w || my < y || my >= y + h {
        hide();
        return None;
    }
    let menu_type = get_type()?;
    find_clicked_item(my, y, get_items(menu_type))
}

pub fn contains_point(mx: i32, my: i32) -> bool {
    if !is_visible() {
        return false;
    }
    let (x, y, w, h) = get_bounds();
    mx >= x && mx < x + w && my >= y && my < y + h
}

fn get_bounds() -> (i32, i32, i32, i32) {
    (
        MENU_X.load(Ordering::Relaxed),
        MENU_Y.load(Ordering::Relaxed),
        MENU_WIDTH.load(Ordering::Relaxed),
        MENU_HEIGHT.load(Ordering::Relaxed),
    )
}

fn get_type() -> Option<ContextMenuType> {
    match MENU_TYPE.load(Ordering::Relaxed) {
        1 => Some(ContextMenuType::Desktop),
        2 => Some(ContextMenuType::FileManager),
        3 => Some(ContextMenuType::TextEditor),
        4 => Some(ContextMenuType::Window),
        _ => None,
    }
}

fn find_hover_item(my: i32, y: i32, items: &[super::types::MenuItem]) {
    let mut item_y = y + MENU_PADDING as i32;
    for (i, item) in items.iter().enumerate() {
        let item_h =
            if item.item_type == MenuItemType::Separator { 9 } else { MENU_ITEM_HEIGHT as i32 };
        if my >= item_y && my < item_y + item_h {
            let idx = if item.item_type == MenuItemType::Action { i as i32 } else { -1 };
            MENU_HOVER_INDEX.store(idx, Ordering::Relaxed);
            return;
        }
        item_y += item_h;
    }
    MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
}

fn find_clicked_item(my: i32, y: i32, items: &[super::types::MenuItem]) -> Option<u8> {
    let mut item_y = y + MENU_PADDING as i32;
    for item in items {
        let item_h =
            if item.item_type == MenuItemType::Separator { 9 } else { MENU_ITEM_HEIGHT as i32 };
        if my >= item_y && my < item_y + item_h && item.item_type == MenuItemType::Action {
            let action = item.action_id;
            hide();
            return Some(action);
        }
        item_y += item_h;
    }
    None
}
