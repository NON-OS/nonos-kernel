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

pub mod state;
pub mod state_picker;
pub mod buffer;
pub mod buffer_undo;
pub mod buffer_clipboard;
pub mod cursor;
pub mod file;
pub mod render;
pub mod render_ui;
pub mod input;
pub mod input_click;
pub mod find_state;
pub mod find_search;
pub mod find_replace;
pub mod find_input;
pub mod find;
pub mod api;

pub(crate) use state::{
    EDITOR_BUFFER, EDITOR_LEN, EDITOR_CURSOR, EDITOR_MODIFIED, BUFFER_SIZE,
};
pub use api::{
    SpecialKey,
    draw_text_editor,
    handle_text_editor_click,
    editor_key_impl,
    editor_special_key,
    editor_new,
    editor_open,
    editor_save,
    editor_save_as,
    editor_close,
    editor_cursor_left,
    editor_cursor_right,
    editor_cursor_up,
    editor_cursor_down,
    editor_home,
    editor_end,
    editor_delete,
    editor_copy,
    editor_cut,
    editor_paste,
    editor_select_all,
};
pub use find::{
    open_find as editor_open_find,
    open_replace as editor_open_replace,
    close_find as editor_close_find,
    is_active as editor_find_active,
    find_next as editor_find_next,
    find_prev as editor_find_prev,
    replace_one as editor_replace_one,
    replace_all as editor_replace_all,
    set_find_pattern as editor_set_find_pattern,
    set_replace_pattern as editor_set_replace_pattern,
    get_match_count as editor_get_match_count,
    toggle_case_sensitive as editor_toggle_case,
};
