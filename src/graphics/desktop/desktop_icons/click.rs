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

use super::super::constants::MENU_BAR_HEIGHT;
use super::render::get_icon_position;
use super::state::*;
use core::sync::atomic::Ordering;

const ICON_SIZE: u32 = 48;
const ICON_START_X: u32 = 140;

pub(crate) fn handle_click(mx: i32, my: i32, w: u32) -> Option<(&'static str, bool, bool)> {
    let cnt = ICON_COUNT.load(Ordering::SeqCst) as usize;
    let currently_selected = SELECTED_ICON.load(Ordering::SeqCst) as usize;
    for i in 0..cnt {
        let (x, y) = get_icon_position(i, w);
        if mx >= x as i32
            && mx < (x + ICON_SIZE) as i32
            && my >= y as i32
            && my < (y + ICON_SIZE + 16) as i32
        {
            let should_open = currently_selected == i;
            SELECTED_ICON.store(i as u8, Ordering::SeqCst);
            DRAGGING_ICON.store(i as u8, Ordering::SeqCst);
            DRAG_OFFSET_X.store(mx - x as i32, Ordering::SeqCst);
            DRAG_OFFSET_Y.store(my - y as i32, Ordering::SeqCst);
            IS_DRAGGING.store(true, Ordering::SeqCst);
            return build_click_result(i, should_open);
        }
    }
    SELECTED_ICON.store(255, Ordering::SeqCst);
    None
}

fn build_click_result(i: usize, should_open: bool) -> Option<(&'static str, bool, bool)> {
    unsafe {
        init_path();
        static mut PATH_BUF: [u8; MAX_PATH] = [0; MAX_PATH];
        let cur_len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
        PATH_BUF[..cur_len].copy_from_slice(&CURRENT_PATH[..cur_len]);
        PATH_BUF[cur_len] = b'/';
        let name_len = ICONS[i].name_len as usize;
        PATH_BUF[cur_len + 1..cur_len + 1 + name_len].copy_from_slice(&ICONS[i].name[..name_len]);
        let is_dir = ICONS[i].is_dir;
        if let Ok(path) = core::str::from_utf8(&PATH_BUF[..cur_len + 1 + name_len]) {
            return Some((path, is_dir, should_open));
        }
    }
    None
}

pub(crate) fn handle_drag(mx: i32, my: i32) -> bool {
    if !IS_DRAGGING.load(Ordering::SeqCst) {
        return false;
    }
    let idx = DRAGGING_ICON.load(Ordering::SeqCst) as usize;
    if idx >= MAX_ICONS {
        return false;
    }
    let offset_x = DRAG_OFFSET_X.load(Ordering::SeqCst);
    let offset_y = DRAG_OFFSET_Y.load(Ordering::SeqCst);
    let new_x = (mx - offset_x).max(ICON_START_X as i32);
    let new_y = (my - offset_y).max(MENU_BAR_HEIGHT as i32 + 20);
    unsafe {
        ICON_POSITIONS[idx] = (new_x, new_y);
    }
    true
}

pub(crate) fn handle_drag_end() {
    IS_DRAGGING.store(false, Ordering::SeqCst);
    DRAGGING_ICON.store(255, Ordering::SeqCst);
}

pub(crate) fn is_dragging() -> bool {
    IS_DRAGGING.load(Ordering::SeqCst)
}
