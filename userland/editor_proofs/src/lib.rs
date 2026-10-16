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

//! Host proofs for the text editor's document engine. Each `#[path]` include
//! pulls in the real editor source so the tests pin production editing logic,
//! not a copy. The files are included flat at the crate root: for a root-level
//! module, `super::` resolves to the crate root, so their `super::state::State`
//! style imports line up with the sibling includes below.
//!
//! Every include is compiled for the tests alone: nothing links this crate,
//! and outside the test build the editor's items would have no caller.

extern crate alloc;

#[cfg(test)]
#[path = "../../capsule_text_editor/src/doc/mod.rs"]
pub mod doc;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/mode.rs"]
pub mod mode;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/reflow.rs"]
pub mod reflow;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/save_point.rs"]
pub mod save_point;

#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/autoclose.rs"]
pub mod autoclose;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/backspace.rs"]
pub mod backspace;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/byte_at.rs"]
pub mod byte_at;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/caret_nav.rs"]
pub mod caret_nav;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/clamp_scroll.rs"]
pub mod clamp_scroll;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/delete.rs"]
pub mod delete;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/edit.rs"]
pub mod edit;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/find.rs"]
pub mod find;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/highlight.rs"]
pub mod highlight;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/indent.rs"]
pub mod indent;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/insert.rs"]
pub mod insert;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/insert_markup.rs"]
pub mod insert_markup;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/insert_newline.rs"]
pub mod insert_newline;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/language.rs"]
pub mod language;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/layout.rs"]
pub mod layout;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/line_bounds.rs"]
pub mod line_bounds;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/line_ops.rs"]
pub mod line_ops;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/max_scroll.rs"]
pub mod max_scroll;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/open_arg_reply.rs"]
pub mod open_arg_reply;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/open_limit.rs"]
pub mod open_limit;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/position_at.rs"]
pub mod position_at;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/replace.rs"]
pub mod replace;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/save_said.rs"]
pub mod save_said;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/select_word.rs"]
pub mod select_word;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/selection.rs"]
pub mod selection;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/state.rs"]
pub mod state;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/state_new.rs"]
pub mod state_new;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/style_marks.rs"]
pub mod style_marks;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/theme/mod.rs"]
pub mod theme;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/toggle_comment.rs"]
pub mod toggle_comment;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/tree/note.rs"]
pub mod tree_note;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/undo_push.rs"]
pub mod undo_push;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/visual_lines.rs"]
pub mod visual_lines;
#[cfg(test)]
#[path = "../../capsule_text_editor/src/editor/word_nav.rs"]
pub mod word_nav;

#[cfg(test)]
mod edit_tests;
#[cfg(test)]
mod feature_tests;
#[cfg(test)]
mod language_tests;
#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod markup_tests;
#[cfg(test)]
mod open_tests;
#[cfg(test)]
mod save_history_tests;
#[cfg(test)]
mod save_said_tests;
#[cfg(test)]
mod save_tests;
#[cfg(test)]
mod scroll_tests;
#[cfg(test)]
mod shortcut_sheet_tests;
#[cfg(test)]
mod style_marks_tests;
#[cfg(test)]
mod text_bridge_tests;
#[cfg(test)]
mod tree_note_tests;
