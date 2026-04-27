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

pub mod api;
pub mod bracket_match;
pub mod buffer;
pub mod buffer_clipboard;
mod buffer_delete;
mod buffer_indent;
mod buffer_insert;
mod buffer_load;
pub mod buffer_undo;
mod comment_apply;
pub mod comment_toggle;
pub mod cursor;
mod cursor_line;
mod cursor_util;
mod cursor_word;
pub mod file;
mod file_fat32;
mod file_ramfs;
mod file_util;
pub mod find;
pub mod find_counter;
pub mod find_input;
pub mod find_replace;
pub mod find_search;
pub mod find_state;
pub mod goto_line;
pub mod input;
pub mod input_click;
mod redo_apply;
pub mod render;
mod render_linenum;
mod render_picker;
mod render_picker_list;
mod render_status;
mod render_text;
mod render_text_draw;
mod render_toolbar;
pub mod render_ui;
pub mod state;
mod state_path;
pub mod state_picker;
mod state_undo;
pub mod syntax;
mod syntax_c;
mod syntax_js;
mod syntax_nox;
mod syntax_py;
mod syntax_rust;
mod tabs_ops;
mod tabs_render;
pub mod tabs_state;
mod tabs_sync;
mod undo_apply;
mod undo_stack;

pub use api::{
    draw_text_editor, editor_copy, editor_cut, editor_key_impl, editor_open, editor_paste,
    editor_select_all, editor_special_key, handle_text_editor_click, SpecialKey,
};
pub(crate) use state::{BUFFER_SIZE, EDITOR_BUFFER, EDITOR_CURSOR, EDITOR_LEN, EDITOR_MODIFIED};
