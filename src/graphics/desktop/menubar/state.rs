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
pub(super) enum MenuId {
    None = 0,
    App = 1,
    File = 2,
    Edit = 3,
    View = 4,
    Window = 5,
    Help = 6,
    Volume = 7,
    Network = 8,
    Battery = 9,
    User = 10,
}

impl From<u8> for MenuId {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::App,
            2 => Self::File,
            3 => Self::Edit,
            4 => Self::View,
            5 => Self::Window,
            6 => Self::Help,
            7 => Self::Volume,
            8 => Self::Network,
            9 => Self::Battery,
            10 => Self::User,
            _ => Self::None,
        }
    }
}

static ACTIVE_MENU: AtomicU8 = AtomicU8::new(0);

pub(super) fn get_active_menu() -> MenuId {
    MenuId::from(ACTIVE_MENU.load(Ordering::Relaxed))
}

pub(super) fn set_active_menu(menu: MenuId) {
    ACTIVE_MENU.store(menu as u8, Ordering::Relaxed);
}

pub(super) fn toggle_menu(menu: MenuId) {
    let current = get_active_menu();
    if current == menu {
        set_active_menu(MenuId::None);
    } else {
        set_active_menu(menu);
    }
}

pub(super) fn close_all_menus() {
    set_active_menu(MenuId::None);
}
