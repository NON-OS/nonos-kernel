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

use super::state::*;

pub(crate) fn handle_click(x: u32, y: u32, _w: u32, _h: u32, mx: i32, my: i32) -> bool {
    let rx = (mx - x as i32) as u32;
    let ry = (my - y as i32) as u32;
    if ry < 48 {
        return handle_tab_click(rx);
    }
    match current_tab() {
        TAB_PUBLISH => super::publish::handle_click(rx, ry.saturating_sub(50)),
        TAB_MY_APPS => super::my_apps::handle_click(rx, ry.saturating_sub(50)),
        _ => false,
    }
}

fn handle_tab_click(rx: u32) -> bool {
    let tabs = [8u32, 88, 168, 264, 360];
    for (i, &start) in tabs.iter().enumerate() {
        if rx >= start + 20 && rx < start + 80 {
            set_tab(i as u8);
            return true;
        }
    }
    false
}

pub(crate) fn handle_key(ch: u8) {
    match current_tab() {
        TAB_PUBLISH => super::publish::handle_key(ch),
        _ => {}
    }
}
