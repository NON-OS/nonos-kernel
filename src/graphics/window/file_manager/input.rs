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
use crate::graphics::window::state::TITLE_BAR_HEIGHT;
use super::constants::*;
use super::state::{set_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM};
use super::path::{go_up, go_into};
use super::listing::refresh_listing;
use super::operations::{create_folder, delete_selected};
use super::clipboard::{copy_selected, cut_selected, paste};

pub fn handle_file_manager_click(win_x: u32, win_y: u32, win_w: u32, click_x: i32, click_y: i32) -> bool {
    let content_y = (win_y + TITLE_BAR_HEIGHT) as i32;
    let sidebar_w = SIDEBAR_WIDTH as i32;

    if click_x >= win_x as i32 && click_x < win_x as i32 + sidebar_w {
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
        if click_y >= ops_y && click_y < ops_y + 144 {
            let op_row = ((click_y - ops_y) / 24) as usize;
            match op_row {
                0 => {
                    let _ = create_folder("NEWFOLDER");
                }
                1 => {
                    let _ = copy_selected();
                }
                2 => {
                    let _ = cut_selected();
                }
                3 => {
                    let _ = paste();
                }
                4 => {
                    let _ = delete_selected();
                }
                5 => {
                }
                _ => {}
            }
            return true;
        }
    }

    let content_x = (win_x + SIDEBAR_WIDTH) as i32;
    let content_w = win_w - SIDEBAR_WIDTH;

    if click_y >= content_y && click_y < content_y + HEADER_HEIGHT as i32 {
        if click_x >= content_x + content_w as i32 - 80 {
            go_up();
            return true;
        }
    }

    let list_y = content_y + HEADER_HEIGHT as i32 + LIST_HEADER_HEIGHT as i32;
    if click_x >= content_x && click_y >= list_y {
        let row = ((click_y - list_y) / ROW_HEIGHT as i32) as u8;
        let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);

        if row < count {
            let currently_selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
            let entry = unsafe { &FILE_ENTRIES[row as usize] };

            if entry.is_dir {
                if currently_selected == row {
                    let name = unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize]) };
                    go_into(name);
                } else {
                    FM_SELECTED_ITEM.store(row, Ordering::Relaxed);
                }
            } else {
                FM_SELECTED_ITEM.store(row, Ordering::Relaxed);
            }
            return true;
        }
    }

    false
}
