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
use super::constants::*;
use super::listing::refresh_listing;
use super::operations::{create_file, create_folder, delete_selected, rename_selected};
use super::path::{go_into, go_up};
use super::state::{
    clear_input, get_input_text, is_input_active, pop_input_char, push_input_char,
    FM_CREATING_FILE, FM_CREATING_FOLDER, FM_RENAMING,
};
use super::state::{set_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM};
use core::sync::atomic::Ordering;

pub fn handle_file_manager_click(
    win_x: u32,
    win_y: u32,
    win_w: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    let content_y = win_y as i32;
    let sidebar_w = SIDEBAR_WIDTH as i32;

    if click_x >= win_x as i32 && click_x < win_x as i32 + sidebar_w {
        if click_y >= content_y + 36 && click_y < content_y + 36 + 144 {
            let row = ((click_y - content_y - 36) / 36) as usize;
            let paths = ["/ram", "/disk/0", "/disk/1", "/"];
            if row < paths.len() {
                set_path(paths[row]);
                refresh_listing();
                return true;
            }
        }

        let ops_y = content_y + 190 + 24;
        if click_y >= ops_y && click_y < ops_y + 182 {
            let op_row = ((click_y - ops_y) / 26) as usize;
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
                    let name = unsafe {
                        core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize])
                    };
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

fn start_rename() {
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return;
    }

    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    clear_input();
    for &ch in entry.name[..entry.name_len as usize].iter() {
        push_input_char(ch);
    }

    FM_RENAMING.store(true, Ordering::Relaxed);
}

pub fn handle_file_manager_key(ch: u8) -> bool {
    if !is_input_active() {
        return false;
    }

    if ch >= 0x20 && ch < 0x7F {
        push_input_char(ch);
        return true;
    }

    false
}

pub fn handle_file_manager_special_key(key: u8) -> bool {
    if !is_input_active() {
        return false;
    }

    match key {
        0x0E => {
            pop_input_char();
            true
        }
        0x1C => {
            let name = get_input_text();
            if FM_RENAMING.load(Ordering::Relaxed) {
                let _ = rename_selected(name);
                FM_RENAMING.store(false, Ordering::Relaxed);
            } else if FM_CREATING_FOLDER.load(Ordering::Relaxed) {
                if !name.is_empty() {
                    let _ = create_folder(name);
                }
                FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
            } else if FM_CREATING_FILE.load(Ordering::Relaxed) {
                if !name.is_empty() {
                    let _ = create_file(name);
                }
                FM_CREATING_FILE.store(false, Ordering::Relaxed);
            }
            clear_input();
            true
        }
        0x01 => {
            FM_RENAMING.store(false, Ordering::Relaxed);
            FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
            FM_CREATING_FILE.store(false, Ordering::Relaxed);
            clear_input();
            true
        }
        _ => false,
    }
}

pub fn cancel_input() {
    FM_RENAMING.store(false, Ordering::Relaxed);
    FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
    FM_CREATING_FILE.store(false, Ordering::Relaxed);
    clear_input();
}
