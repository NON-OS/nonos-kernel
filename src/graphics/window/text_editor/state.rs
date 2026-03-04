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

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicUsize, AtomicU8, Ordering};

pub(crate) use super::state_picker::{
    picker_open, picker_close, picker_is_active,
    picker_select, picker_get_selected_path, picker_is_selected_dir, picker_navigate_into,
};

pub(crate) const BUFFER_SIZE: usize = 16384;
pub(crate) const PATH_SIZE: usize = 256;
pub(crate) const LINE_HEIGHT: u32 = 18;
pub(crate) const LINE_NUM_WIDTH: u32 = 45;
pub(crate) const TOOLBAR_HEIGHT: u32 = 35;
pub(crate) const STATUS_BAR_HEIGHT: u32 = 25;

pub(crate) const STATUS_NONE: u8 = 0;
pub(crate) const STATUS_SAVED: u8 = 1;
pub(crate) const STATUS_OPENED: u8 = 2;
pub(crate) const STATUS_ERROR: u8 = 3;
pub(crate) const STATUS_NEW: u8 = 4;

pub(crate) static mut EDITOR_BUFFER: [u8; BUFFER_SIZE] = [0u8; BUFFER_SIZE];
pub(crate) static EDITOR_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static EDITOR_CURSOR: AtomicUsize = AtomicUsize::new(0);
pub(crate) static EDITOR_MODIFIED: AtomicBool = AtomicBool::new(false);
pub(crate) static mut EDITOR_FILE_PATH: [u8; PATH_SIZE] = [0u8; PATH_SIZE];
pub(crate) static EDITOR_PATH_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static EDITOR_STATUS: AtomicU8 = AtomicU8::new(0);
pub(crate) static EDITOR_SCROLL_Y: AtomicUsize = AtomicUsize::new(0);
pub(crate) static EDITOR_SELECTION_START: AtomicUsize = AtomicUsize::new(0);
pub(crate) static EDITOR_SELECTION_END: AtomicUsize = AtomicUsize::new(0);
pub(crate) static EDITOR_HAS_SELECTION: AtomicBool = AtomicBool::new(false);

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
        Self {
            op_type: UndoOpType::None,
            cursor_pos: 0,
            data_len: 0,
            data: [0u8; UNDO_DATA_SIZE],
        }
    }
}

pub(crate) static mut UNDO_STACK: [UndoEntry; UNDO_STACK_SIZE] = [UndoEntry::empty(); UNDO_STACK_SIZE];
pub(crate) static UNDO_TOP: AtomicUsize = AtomicUsize::new(0);
pub(crate) static mut REDO_STACK: [UndoEntry; UNDO_STACK_SIZE] = [UndoEntry::empty(); UNDO_STACK_SIZE];
pub(crate) static REDO_TOP: AtomicUsize = AtomicUsize::new(0);

pub(crate) const MAX_PICKER_FILES: usize = 32;
pub(crate) const MAX_PICKER_NAME: usize = 64;
pub(crate) static PICKER_ACTIVE: AtomicBool = AtomicBool::new(false);
pub(crate) static PICKER_SELECTED: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PICKER_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(crate) static mut PICKER_FILES: [[u8; MAX_PICKER_NAME]; MAX_PICKER_FILES] = [[0u8; MAX_PICKER_NAME]; MAX_PICKER_FILES];
pub(crate) static mut PICKER_LENS: [usize; MAX_PICKER_FILES] = [0usize; MAX_PICKER_FILES];
pub(crate) static mut PICKER_IS_DIR: [bool; MAX_PICKER_FILES] = [false; MAX_PICKER_FILES];
pub(crate) static mut PICKER_PATH: [u8; PATH_SIZE] = [0u8; PATH_SIZE];
pub(crate) static PICKER_PATH_LEN: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn reset_state() {
    unsafe {
        for i in 0..BUFFER_SIZE {
            EDITOR_BUFFER[i] = 0;
        }
        for i in 0..PATH_SIZE {
            EDITOR_FILE_PATH[i] = 0;
        }
    }
    EDITOR_LEN.store(0, Ordering::Relaxed);
    EDITOR_CURSOR.store(0, Ordering::Relaxed);
    EDITOR_MODIFIED.store(false, Ordering::Relaxed);
    EDITOR_PATH_LEN.store(0, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    EDITOR_SCROLL_Y.store(0, Ordering::Relaxed);
    EDITOR_HAS_SELECTION.store(false, Ordering::Relaxed);
    UNDO_TOP.store(0, Ordering::Relaxed);
    REDO_TOP.store(0, Ordering::Relaxed);
}

pub(crate) fn set_path(path: &str) {
    let path_bytes = path.as_bytes();
    let path_len = path_bytes.len().min(PATH_SIZE - 1);
    unsafe {
        for i in 0..path_len {
            EDITOR_FILE_PATH[i] = path_bytes[i];
        }
        for i in path_len..PATH_SIZE {
            EDITOR_FILE_PATH[i] = 0;
        }
    }
    EDITOR_PATH_LEN.store(path_len, Ordering::Relaxed);
}

pub(crate) fn get_path() -> Option<&'static str> {
    let len = EDITOR_PATH_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return None;
    }
    unsafe {
        core::str::from_utf8(&EDITOR_FILE_PATH[..len]).ok()
    }
}

pub(crate) fn get_buffer_slice() -> &'static [u8] {
    let len = EDITOR_LEN.load(Ordering::Relaxed);
    unsafe { &EDITOR_BUFFER[..len] }
}
