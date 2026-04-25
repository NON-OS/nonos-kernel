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

pub(crate) fn handle_click(x: u32, y: u32, w: u32, _h: u32, mx: i32, my: i32) -> bool {
    let rx = (mx - x as i32) as u32;
    let ry = (my - y as i32) as u32;
    if ry < 50 {
        return handle_header_click(rx, w);
    }
    match view() {
        VIEW_LIST => handle_list_click(rx, ry - 50, w),
        VIEW_CHAT => super::chat::handle_click(rx, ry - 50),
        VIEW_CREATE => super::create::handle_click(rx, ry - 50),
        _ => false,
    }
}

fn handle_header_click(rx: u32, w: u32) -> bool {
    let ts = w - 260;
    if rx >= ts && rx < ts + 72 {
        set_view(VIEW_DASHBOARD);
        return true;
    }
    if rx >= ts + 88 && rx < ts + 136 {
        set_view(VIEW_LIST);
        return true;
    }
    if rx >= ts + 152 && rx < ts + 200 {
        set_view(VIEW_CREATE);
        return true;
    }
    false
}

fn handle_list_click(rx: u32, ry: u32, w: u32) -> bool {
    let agents = crate::agents::registry::list_agents();
    let idx = (ry / 70) as usize;
    if idx < agents.len() {
        let (id, _) = agents[idx];
        if rx >= w - 100 && rx < w - 20 {
            set_selected(id);
            set_view(VIEW_CHAT);
            return true;
        }
        set_selected(id);
        return true;
    }
    false
}

pub(crate) fn handle_key(ch: u8) {
    match view() {
        VIEW_CHAT => super::chat::handle_key(ch),
        VIEW_CREATE => super::create::handle_key(ch),
        _ => {}
    }
}
