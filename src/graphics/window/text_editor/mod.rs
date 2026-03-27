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
mod state_undo;
mod state_path;
pub mod buffer;
mod buffer_insert;
mod buffer_delete;
mod buffer_load;
mod buffer_indent;
pub mod buffer_undo;
mod undo_stack;
mod undo_apply;
mod redo_apply;
pub mod buffer_clipboard;
pub mod cursor;
mod cursor_line;
mod cursor_word;
mod cursor_util;
pub mod file;
mod file_util;
mod file_ramfs;
mod file_fat32;
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
pub mod syntax;
mod syntax_rust;
mod syntax_js;
mod syntax_py;
mod syntax_c;
mod syntax_nox;
mod render_text;
mod render_text_draw;
mod render_toolbar;
pub mod tabs_state;
mod tabs_sync;
mod tabs_ops;
mod tabs_render;
mod render_picker;
mod render_picker_list;
mod render_status;
mod render_linenum;
pub mod bracket_match;
pub mod comment_toggle;
mod comment_apply;
pub mod goto_line;
pub mod find_counter;

pub(crate) use state::{EDITOR_BUFFER, EDITOR_LEN, EDITOR_CURSOR, EDITOR_MODIFIED, BUFFER_SIZE};
pub use api::{SpecialKey, draw_text_editor, handle_text_editor_click, editor_key_impl, editor_special_key, editor_cut, editor_copy, editor_paste, editor_select_all, editor_open};
