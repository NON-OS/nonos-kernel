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

pub(super) use super::buffer_clipboard::{copy_selection, cut_selection, paste};
pub(super) use super::buffer_delete::{delete_backward, delete_forward, delete_selection};
pub(super) use super::buffer_insert::{insert_char, insert_newline, insert_str, insert_tab};
pub(super) use super::buffer_load::{load_content, select_all};
pub(super) use super::buffer_undo::{redo, undo};
