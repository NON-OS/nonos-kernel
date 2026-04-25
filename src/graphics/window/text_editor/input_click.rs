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
use super::{cursor, file};
use core::sync::atomic::Ordering;

pub(super) fn handle_click(
    win_x: u32,
    win_y: u32,
    win_w: u32,
    win_h: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    use super::state::picker_is_active;
    use super::tabs_render::{handle_tab_click, TAB_BAR_HEIGHT};
    use super::tabs_state::tabs_enabled;

    let content_y = win_y;

    if picker_is_active() {
        return handle_picker_click(win_x, content_y, win_w, win_h, click_x, click_y);
    }

    let tab_offset = if tabs_enabled() { TAB_BAR_HEIGHT } else { 0 };
    if tabs_enabled() && click_y >= content_y as i32 && click_y < (content_y + tab_offset) as i32 {
        return handle_tab_click(win_x, content_y, click_x as u32);
    }

    let toolbar_y = content_y + tab_offset;
    if handle_toolbar_click(win_x, toolbar_y, click_x, click_y) {
        return true;
    }

    if handle_text_area_click(win_x, content_y, win_w, win_h, click_x, click_y) {
        return true;
    }

    false
}

pub(super) fn handle_picker_click(
    win_x: u32,
    content_y: u32,
    win_w: u32,
    win_h: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    use super::state::{
        get_save_path, picker_close, picker_get_selected_path, picker_is_save_mode,
        picker_is_selected_dir, picker_navigate_into, picker_select, PICKER_COUNT, PICKER_SELECTED,
    };

    let is_save = picker_is_save_mode();
    let picker_x = win_x + 20;
    let picker_y = content_y + if is_save { 80 } else { 40 };
    let picker_w = win_w - 40;
    let row_height = 28u32;

    let cancel_x = win_x + win_w - 80;
    let cancel_y = content_y + win_h - 48;
    if click_x >= cancel_x as i32
        && click_x < (cancel_x + 60) as i32
        && click_y >= cancel_y as i32
        && click_y < (cancel_y + 25) as i32
    {
        picker_close();
        return true;
    }

    let action_x = win_x + win_w - 150;
    if click_x >= action_x as i32
        && click_x < (action_x + 60) as i32
        && click_y >= cancel_y as i32
        && click_y < (cancel_y + 25) as i32
    {
        if is_save {
            if let Some(path) = get_save_path() {
                picker_close();
                file::save_file_as(&path);
            }
        } else if picker_is_selected_dir() {
            picker_navigate_into();
        } else if let Some(path) = picker_get_selected_path() {
            picker_close();
            file::open_file(&path);
        }
        return true;
    }

    if click_x >= picker_x as i32 && click_x < (picker_x + picker_w) as i32 {
        let rel_y = click_y - picker_y as i32;
        if rel_y >= 0 {
            let row = (rel_y / row_height as i32) as usize;
            let count = PICKER_COUNT.load(Ordering::Relaxed);
            if row < count {
                let current = PICKER_SELECTED.load(Ordering::Relaxed);
                if row == current {
                    if picker_is_selected_dir() {
                        picker_navigate_into();
                    } else if !is_save {
                        if let Some(path) = picker_get_selected_path() {
                            picker_close();
                            file::open_file(&path);
                        }
                    }
                } else {
                    picker_select(row);
                }
                return true;
            }
        }
    }

    true
}

pub(super) fn handle_toolbar_click(win_x: u32, content_y: u32, click_x: i32, click_y: i32) -> bool {
    use super::state::picker_open_save;

    if click_y < content_y as i32 + 5 || click_y > content_y as i32 + 30 {
        return false;
    }

    let rel_x = click_x - win_x as i32 - 8;

    if rel_x >= 0 && rel_x < 40 {
        file::new_file();
        return true;
    }
    if rel_x >= 46 && rel_x < 94 {
        super::state::picker_open("/ram");
        return true;
    }
    if rel_x >= 100 && rel_x < 148 {
        file::save_file();
        return true;
    }
    if rel_x >= 154 && rel_x < 214 {
        picker_open_save("/ram");
        return true;
    }
    if rel_x >= 220 && rel_x < 272 {
        file::close_file();
        return true;
    }

    false
}

pub(super) fn handle_text_area_click(
    win_x: u32,
    content_y: u32,
    win_w: u32,
    win_h: u32,
    click_x: i32,
    click_y: i32,
) -> bool {
    let text_area_x = win_x + LINE_NUM_WIDTH + 10;
    let text_area_y = content_y + TOOLBAR_HEIGHT + 10;
    let text_area_end_y = content_y + win_h - STATUS_BAR_HEIGHT;
    let chars_per_line = ((win_w - LINE_NUM_WIDTH - 20) / 8) as usize;

    if click_x < text_area_x as i32
        || click_y < text_area_y as i32
        || click_y >= text_area_end_y as i32
    {
        return false;
    }

    let scroll_y = EDITOR_SCROLL_Y.load(Ordering::Relaxed);
    let clicked_display_line = ((click_y - text_area_y as i32) / LINE_HEIGHT as i32) as usize;
    let clicked_col = ((click_x - text_area_x as i32) / 8) as usize;
    let target_line = scroll_y + clicked_display_line;

    let editor_len = EDITOR_LEN.load(Ordering::Relaxed);
    let mut current_line = 0usize;
    let mut current_col = 0usize;
    let mut char_idx = 0usize;

    // SAFETY: Single-threaded access to editor buffer during click handling
    unsafe {
        while char_idx < editor_len {
            if current_line == target_line && current_col == clicked_col {
                cursor::set_position(char_idx);
                EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
                return true;
            }

            if EDITOR_BUFFER[char_idx] == b'\n' {
                if current_line == target_line {
                    cursor::set_position(char_idx);
                    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
                    return true;
                }
                current_line += 1;
                current_col = 0;
            } else {
                current_col += 1;
                if current_col >= chars_per_line {
                    if current_line == target_line {
                        cursor::set_position(char_idx + 1);
                        EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
                        return true;
                    }
                    current_col = 0;
                    current_line += 1;
                }
            }

            char_idx += 1;
        }

        if current_line == target_line {
            cursor::set_position(editor_len);
            EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
            return true;
        }
    }

    false
}
