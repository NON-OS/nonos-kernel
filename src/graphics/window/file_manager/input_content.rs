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

use super::constants::*;
use super::path::{go_into, go_up};
use super::state::{FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM};
use core::sync::atomic::Ordering;

pub fn handle_content_click(
    win_x: u32,
    win_w: u32,
    content_y: i32,
    click_x: i32,
    click_y: i32,
) -> bool {
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
        return handle_list_click(click_y, list_y);
    }

    false
}

fn handle_list_click(click_y: i32, list_y: i32) -> bool {
    let row = ((click_y - list_y) / ROW_HEIGHT as i32) as u8;
    let count = FILE_ENTRY_COUNT.load(Ordering::Relaxed);

    if row < count {
        let currently_selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
        let entry = unsafe { &FILE_ENTRIES[row as usize] };

        if entry.is_dir && currently_selected == row {
            let name =
                unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize]) };
            go_into(name);
        } else {
            FM_SELECTED_ITEM.store(row, Ordering::Relaxed);
        }
        return true;
    }

    false
}
