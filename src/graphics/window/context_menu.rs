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

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use crate::graphics::framebuffer::fill_rect;
use crate::graphics::font::draw_char;

pub const MAX_MENU_ITEMS: usize = 10;
pub(super) const MENU_ITEM_HEIGHT: u32 = 28;
pub(super) const MENU_PADDING: u32 = 4;
const MENU_MIN_WIDTH: u32 = 150;

const COLOR_MENU_BG: u32 = 0xFF1C2128;
const COLOR_MENU_BORDER: u32 = 0xFF30363D;
const COLOR_MENU_HOVER: u32 = 0xFF2D333B;
const COLOR_MENU_TEXT: u32 = 0xFFE6EDF3;
const COLOR_MENU_TEXT_DIM: u32 = 0xFF7D8590;
const COLOR_SEPARATOR: u32 = 0xFF30363D;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MenuItemType {
    Action,
    Separator,
    Disabled,
}

#[derive(Clone, Copy)]
pub struct MenuItem {
    pub label: &'static [u8],
    pub item_type: MenuItemType,
    pub action_id: u8,
}

impl MenuItem {
    pub const fn action(label: &'static [u8], action_id: u8) -> Self {
        Self { label, item_type: MenuItemType::Action, action_id }
    }

    pub const fn separator() -> Self {
        Self { label: b"", item_type: MenuItemType::Separator, action_id: 0 }
    }

    pub const fn disabled(label: &'static [u8]) -> Self {
        Self { label, item_type: MenuItemType::Disabled, action_id: 0 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContextMenuType {
    None = 0,
    Desktop = 1,
    FileManager = 2,
    TextEditor = 3,
    Window = 4,
}

pub(super) static MENU_VISIBLE: AtomicBool = AtomicBool::new(false);
pub(super) static MENU_X: AtomicI32 = AtomicI32::new(0);
pub(super) static MENU_Y: AtomicI32 = AtomicI32::new(0);
pub(super) static MENU_WIDTH: AtomicI32 = AtomicI32::new(0);
pub(super) static MENU_HEIGHT: AtomicI32 = AtomicI32::new(0);
pub(super) static MENU_TYPE: AtomicU8 = AtomicU8::new(0);
pub(super) static MENU_HOVER_INDEX: AtomicI32 = AtomicI32::new(-1);
static MENU_ITEM_COUNT: AtomicU8 = AtomicU8::new(0);

pub mod actions {
    pub const DESKTOP_REFRESH: u8 = 1;
    pub const DESKTOP_SETTINGS: u8 = 2;
    pub const DESKTOP_ABOUT: u8 = 3;
    pub const FM_OPEN: u8 = 10;
    pub const FM_COPY: u8 = 11;
    pub const FM_CUT: u8 = 12;
    pub const FM_PASTE: u8 = 13;
    pub const FM_DELETE: u8 = 14;
    pub const FM_RENAME: u8 = 15;
    pub const FM_NEW_FOLDER: u8 = 16;
    pub const FM_PROPERTIES: u8 = 17;
    pub const EDIT_CUT: u8 = 20;
    pub const EDIT_COPY: u8 = 21;
    pub const EDIT_PASTE: u8 = 22;
    pub const EDIT_SELECT_ALL: u8 = 23;
    pub const WIN_MINIMIZE: u8 = 30;
    pub const WIN_MAXIMIZE: u8 = 31;
    pub const WIN_CLOSE: u8 = 32;
}

static MENU_DESKTOP: [MenuItem; 4] = [
    MenuItem::action(b"Refresh", actions::DESKTOP_REFRESH),
    MenuItem::separator(),
    MenuItem::action(b"Settings", actions::DESKTOP_SETTINGS),
    MenuItem::action(b"About N\xd8NOS", actions::DESKTOP_ABOUT),
];

static MENU_FILE_MANAGER: [MenuItem; 10] = [
    MenuItem::action(b"Open", actions::FM_OPEN),
    MenuItem::separator(),
    MenuItem::action(b"Cut", actions::FM_CUT),
    MenuItem::action(b"Copy", actions::FM_COPY),
    MenuItem::action(b"Paste", actions::FM_PASTE),
    MenuItem::separator(),
    MenuItem::action(b"Delete", actions::FM_DELETE),
    MenuItem::action(b"Rename", actions::FM_RENAME),
    MenuItem::separator(),
    MenuItem::action(b"New Folder", actions::FM_NEW_FOLDER),
];

static MENU_TEXT_EDITOR: [MenuItem; 5] = [
    MenuItem::action(b"Cut", actions::EDIT_CUT),
    MenuItem::action(b"Copy", actions::EDIT_COPY),
    MenuItem::action(b"Paste", actions::EDIT_PASTE),
    MenuItem::separator(),
    MenuItem::action(b"Select All", actions::EDIT_SELECT_ALL),
];

static MENU_WINDOW: [MenuItem; 4] = [
    MenuItem::action(b"Minimize", actions::WIN_MINIMIZE),
    MenuItem::action(b"Maximize", actions::WIN_MAXIMIZE),
    MenuItem::separator(),
    MenuItem::action(b"Close", actions::WIN_CLOSE),
];

static MENU_EMPTY: [MenuItem; 0] = [];

pub(super) fn get_menu_items(menu_type: ContextMenuType) -> &'static [MenuItem] {
    match menu_type {
        ContextMenuType::Desktop => &MENU_DESKTOP,
        ContextMenuType::FileManager => &MENU_FILE_MANAGER,
        ContextMenuType::TextEditor => &MENU_TEXT_EDITOR,
        ContextMenuType::Window => &MENU_WINDOW,
        ContextMenuType::None => &MENU_EMPTY,
    }
}

pub fn show(x: i32, y: i32, menu_type: ContextMenuType) {
    let items = get_menu_items(menu_type);
    if items.is_empty() {
        return;
    }

    let mut max_width = MENU_MIN_WIDTH;
    let mut height = MENU_PADDING * 2;
    let mut item_count = 0u8;

    for item in items {
        if item.item_type == MenuItemType::Separator {
            height += 9;
        } else {
            height += MENU_ITEM_HEIGHT;
            let label_width = (item.label.len() as u32) * 8 + MENU_PADDING * 4;
            if label_width > max_width {
                max_width = label_width;
            }
        }
        item_count += 1;
    }

    let (screen_w, screen_h) = crate::graphics::framebuffer::dimensions();
    let final_x = if x + max_width as i32 > screen_w as i32 {
        (screen_w as i32 - max_width as i32).max(0)
    } else {
        x
    };
    let final_y = if y + height as i32 > screen_h as i32 {
        (screen_h as i32 - height as i32).max(0)
    } else {
        y
    };

    MENU_X.store(final_x, Ordering::Relaxed);
    MENU_Y.store(final_y, Ordering::Relaxed);
    MENU_WIDTH.store(max_width as i32, Ordering::Relaxed);
    MENU_HEIGHT.store(height as i32, Ordering::Relaxed);
    MENU_TYPE.store(menu_type as u8, Ordering::Relaxed);
    MENU_ITEM_COUNT.store(item_count, Ordering::Relaxed);
    MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
    MENU_VISIBLE.store(true, Ordering::Relaxed);
}

pub fn hide() {
    MENU_VISIBLE.store(false, Ordering::Relaxed);
}

pub fn is_visible() -> bool {
    MENU_VISIBLE.load(Ordering::Relaxed)
}

pub fn draw() {
    if !is_visible() {
        return;
    }

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

    let items = get_menu_items(menu_type);

    fill_rect(x, y, w, h, COLOR_MENU_BG);
    fill_rect(x, y, w, 1, COLOR_MENU_BORDER);
    fill_rect(x, y + h - 1, w, 1, COLOR_MENU_BORDER);
    fill_rect(x, y, 1, h, COLOR_MENU_BORDER);
    fill_rect(x + w - 1, y, 1, h, COLOR_MENU_BORDER);

    let mut item_y = y + MENU_PADDING;
    for (i, item) in items.iter().enumerate() {
        if item.item_type == MenuItemType::Separator {
            fill_rect(x + MENU_PADDING, item_y + 4, w - MENU_PADDING * 2, 1, COLOR_SEPARATOR);
            item_y += 9;
        } else {
            if hover_idx == i as i32 && item.item_type == MenuItemType::Action {
                fill_rect(x + 2, item_y, w - 4, MENU_ITEM_HEIGHT, COLOR_MENU_HOVER);
            }

            let text_color = if item.item_type == MenuItemType::Disabled {
                COLOR_MENU_TEXT_DIM
            } else {
                COLOR_MENU_TEXT
            };

            let text_x = x + MENU_PADDING * 2;
            let text_y = item_y + (MENU_ITEM_HEIGHT - 16) / 2;
            for (j, &ch) in item.label.iter().enumerate() {
                draw_char(text_x + (j as u32) * 8, text_y, ch, text_color);
            }

            item_y += MENU_ITEM_HEIGHT;
        }
    }
}

pub use super::context_menu_input::{update_hover, handle_click, contains_point};
