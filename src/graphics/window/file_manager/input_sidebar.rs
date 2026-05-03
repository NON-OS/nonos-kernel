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

use super::clipboard::{copy_selected, cut_selected, paste};
use super::input_rename::start_rename;
use super::listing::refresh_listing;
use super::operations::delete_selected;
use super::state::{clear_input, set_path, FM_CREATING_FILE, FM_CREATING_FOLDER};
use core::sync::atomic::Ordering;

pub fn handle_sidebar_click(_win_x: u32, content_y: i32, _click_x: i32, click_y: i32) -> bool {
    if click_y >= content_y + 40 && click_y < content_y + 40 + 128 {
        let row = ((click_y - content_y - 40) / 32) as usize;
        let paths = ["/ram", "/disk/0", "/disk/1", "/"];
        if row < paths.len() {
            set_path(paths[row]);
            refresh_listing();
            return true;
        }
    }

    let ops_y = content_y + 210;
    if click_y >= ops_y && click_y < ops_y + 176 {
        let op_row = ((click_y - ops_y) / 22) as usize;
        handle_action(op_row);
        return true;
    }

    false
}

fn handle_action(op_row: usize) {
    match op_row {
        0 => {
            clear_input();
            FM_CREATING_FOLDER.store(true, Ordering::Relaxed);
        }
        1 => {
            clear_input();
            FM_CREATING_FILE.store(true, Ordering::Relaxed);
        }
        2 => {
            let _ = copy_selected();
        }
        3 => {
            let _ = cut_selected();
        }
        4 => {
            let _ = paste();
        }
        5 => {
            let _ = delete_selected();
        }
        6 => {
            start_rename();
        }
        _ => {}
    }
}
