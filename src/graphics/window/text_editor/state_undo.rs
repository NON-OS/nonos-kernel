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

use core::sync::atomic::AtomicUsize;

pub(crate) const UNDO_STACK_SIZE: usize = 64;
pub(crate) const UNDO_DATA_SIZE: usize = 256;

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum UndoOpType {
    None,
    Insert,
    Delete,
}

#[derive(Clone, Copy)]
pub(crate) struct UndoEntry {
    pub op_type: UndoOpType,
    pub cursor_pos: usize,
    pub data_len: usize,
    pub data: [u8; UNDO_DATA_SIZE],
}

impl UndoEntry {
    pub(crate) const fn empty() -> Self {
        Self { op_type: UndoOpType::None, cursor_pos: 0, data_len: 0, data: [0u8; UNDO_DATA_SIZE] }
    }
}

pub(crate) static mut UNDO_STACK: [UndoEntry; UNDO_STACK_SIZE] =
    [UndoEntry::empty(); UNDO_STACK_SIZE];
pub(crate) static UNDO_TOP: AtomicUsize = AtomicUsize::new(0);
pub(crate) static mut REDO_STACK: [UndoEntry; UNDO_STACK_SIZE] =
    [UndoEntry::empty(); UNDO_STACK_SIZE];
pub(crate) static REDO_TOP: AtomicUsize = AtomicUsize::new(0);
