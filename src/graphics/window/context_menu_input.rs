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
use super::context_menu::{
    MENU_X, MENU_Y, MENU_WIDTH, MENU_HEIGHT, MENU_TYPE, MENU_HOVER_INDEX, MENU_PADDING,
    MENU_ITEM_HEIGHT, ContextMenuType, MenuItemType, get_menu_items, is_visible, hide,
};

pub fn update_hover(mx: i32, my: i32) {
    if !is_visible() {
        return;
    }

    let x = MENU_X.load(Ordering::Relaxed);
    let y = MENU_Y.load(Ordering::Relaxed);
    let w = MENU_WIDTH.load(Ordering::Relaxed);
    let h = MENU_HEIGHT.load(Ordering::Relaxed);

    if mx < x || mx >= x + w || my < y || my >= y + h {
        MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
        return;
    }

    let menu_type = match MENU_TYPE.load(Ordering::Relaxed) {
        1 => ContextMenuType::Desktop,
        2 => ContextMenuType::FileManager,
        3 => ContextMenuType::TextEditor,
        4 => ContextMenuType::Window,
        _ => return,
    };

    let items = get_menu_items(menu_type);

    let mut item_y = y + MENU_PADDING as i32;
    for (i, item) in items.iter().enumerate() {
        let item_h = if item.item_type == MenuItemType::Separator { 9 } else { MENU_ITEM_HEIGHT as i32 };

        if my >= item_y && my < item_y + item_h {
            if item.item_type == MenuItemType::Action {
                MENU_HOVER_INDEX.store(i as i32, Ordering::Relaxed);
            } else {
                MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
            }
            return;
        }
        item_y += item_h;
    }

    MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
}

pub fn handle_click(mx: i32, my: i32) -> Option<u8> {
    if !is_visible() {
        return None;
    }

    let x = MENU_X.load(Ordering::Relaxed);
    let y = MENU_Y.load(Ordering::Relaxed);
    let w = MENU_WIDTH.load(Ordering::Relaxed);
    let h = MENU_HEIGHT.load(Ordering::Relaxed);

    if mx < x || mx >= x + w || my < y || my >= y + h {
        hide();
        return None;
    }

    let menu_type = match MENU_TYPE.load(Ordering::Relaxed) {
        1 => ContextMenuType::Desktop,
        2 => ContextMenuType::FileManager,
        3 => ContextMenuType::TextEditor,
        4 => ContextMenuType::Window,
        _ => {
            hide();
            return None;
        }
    };

    let items = get_menu_items(menu_type);

    let mut item_y = y + MENU_PADDING as i32;
    for item in items {
        let item_h = if item.item_type == MenuItemType::Separator { 9 } else { MENU_ITEM_HEIGHT as i32 };

        if my >= item_y && my < item_y + item_h {
            if item.item_type == MenuItemType::Action {
                let action = item.action_id;
                hide();
                return Some(action);
            }
            return None;
        }
        item_y += item_h;
    }

    None
}

pub fn contains_point(mx: i32, my: i32) -> bool {
    if !is_visible() {
        return false;
    }

    let x = MENU_X.load(Ordering::Relaxed);
    let y = MENU_Y.load(Ordering::Relaxed);
    let w = MENU_WIDTH.load(Ordering::Relaxed);
    let h = MENU_HEIGHT.load(Ordering::Relaxed);

    mx >= x && mx < x + w && my >= y && my < y + h
}
