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

use core::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrayMenu {
    None = 0,
    Wifi = 1,
    Bluetooth = 2,
    Sound = 3,
    Control = 4,
}

static ACTIVE_MENU: AtomicU8 = AtomicU8::new(0);
static HOVERED_ITEM: AtomicU8 = AtomicU8::new(0);

pub fn get_active() -> TrayMenu {
    match ACTIVE_MENU.load(Ordering::Relaxed) {
        1 => TrayMenu::Wifi,
        2 => TrayMenu::Bluetooth,
        3 => TrayMenu::Sound,
        4 => TrayMenu::Control,
        _ => TrayMenu::None,
    }
}

pub fn is_any_open() -> bool {
    ACTIVE_MENU.load(Ordering::Relaxed) != 0
}

pub fn toggle(menu: TrayMenu) {
    let current = ACTIVE_MENU.load(Ordering::Relaxed);
    if current == menu as u8 {
        ACTIVE_MENU.store(0, Ordering::Relaxed);
    } else {
        ACTIVE_MENU.store(menu as u8, Ordering::Relaxed);
    }
    HOVERED_ITEM.store(0, Ordering::Relaxed);
}

pub fn close_all() {
    ACTIVE_MENU.store(0, Ordering::Relaxed);
    HOVERED_ITEM.store(0, Ordering::Relaxed);
}

pub(super) fn get_hovered() -> u8 {
    HOVERED_ITEM.load(Ordering::Relaxed)
}

pub(super) fn set_hovered(idx: u8) {
    HOVERED_ITEM.store(idx, Ordering::Relaxed);
}

pub fn handle_click(mx: i32, my: i32, sw: u32) -> bool {
    let menu = get_active();
    if menu == TrayMenu::None {
        return false;
    }
    let (x, y, w, h) = super::render::menu_bounds(menu, sw);
    if mx < x || mx >= x + w as i32 || my < y || my >= y + h as i32 {
        close_all();
        return true;
    }
    let rel_y = my - y;
    let item = (rel_y / 36) as u8;
    dispatch_click(menu, item);
    true
}

fn dispatch_click(menu: TrayMenu, item: u8) {
    match menu {
        TrayMenu::Wifi => super::wifi::handle_item_click(item),
        TrayMenu::Bluetooth => super::bluetooth::handle_item_click(item),
        TrayMenu::Sound => super::sound::handle_item_click(item),
        TrayMenu::Control => super::control::handle_item_click(item),
        TrayMenu::None => {}
    }
}
