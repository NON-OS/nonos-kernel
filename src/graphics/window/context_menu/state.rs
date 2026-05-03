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
use super::types::{ContextMenuType, MenuItemType};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

pub const MENU_ITEM_HEIGHT: u32 = 28;
pub const MENU_PADDING: u32 = 4;
const MENU_MIN_WIDTH: u32 = 150;

pub static MENU_VISIBLE: AtomicBool = AtomicBool::new(false);
pub static MENU_X: AtomicI32 = AtomicI32::new(0);
pub static MENU_Y: AtomicI32 = AtomicI32::new(0);
pub static MENU_WIDTH: AtomicI32 = AtomicI32::new(0);
pub static MENU_HEIGHT: AtomicI32 = AtomicI32::new(0);
pub static MENU_TYPE: AtomicU8 = AtomicU8::new(0);
pub static MENU_HOVER_INDEX: AtomicI32 = AtomicI32::new(-1);

pub fn show(x: i32, y: i32, menu_type: ContextMenuType) {
    let items = get_items(menu_type);
    if items.is_empty() {
        return;
    }

    let (max_width, height) = calculate_dimensions(items);
    let (final_x, final_y) = clamp_to_screen(x, y, max_width, height);

    MENU_X.store(final_x, Ordering::Relaxed);
    MENU_Y.store(final_y, Ordering::Relaxed);
    MENU_WIDTH.store(max_width as i32, Ordering::Relaxed);
    MENU_HEIGHT.store(height as i32, Ordering::Relaxed);
    MENU_TYPE.store(menu_type as u8, Ordering::Relaxed);
    MENU_HOVER_INDEX.store(-1, Ordering::Relaxed);
    MENU_VISIBLE.store(true, Ordering::Relaxed);
}

fn calculate_dimensions(items: &[super::types::MenuItem]) -> (u32, u32) {
    let mut max_width = MENU_MIN_WIDTH;
    let mut height = MENU_PADDING * 2;
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
    }
    (max_width, height)
}

fn clamp_to_screen(x: i32, y: i32, w: u32, h: u32) -> (i32, i32) {
    let (sw, sh) = crate::display::framebuffer::dimensions();
    let fx = if x + w as i32 > sw as i32 { (sw as i32 - w as i32).max(0) } else { x };
    let fy = if y + h as i32 > sh as i32 { (sh as i32 - h as i32).max(0) } else { y };
    (fx, fy)
}

pub fn hide() {
    MENU_VISIBLE.store(false, Ordering::Relaxed);
}
pub fn is_visible() -> bool {
    MENU_VISIBLE.load(Ordering::Relaxed)
}
