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

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

pub(crate) use super::state_path::{get_buffer_slice, get_path, set_path};
pub(crate) use super::state_picker::{
    get_save_filename, get_save_path, picker_close, picker_get_selected_path, picker_is_active,
    picker_is_save_mode, picker_is_selected_dir, picker_navigate_into, picker_open,
    picker_open_save, picker_select, save_filename_input,
};
pub(crate) use super::state_undo::{
    UndoEntry, UndoOpType, REDO_STACK, REDO_TOP, UNDO_DATA_SIZE, UNDO_STACK, UNDO_STACK_SIZE,
    UNDO_TOP,
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

pub(crate) const MAX_PICKER_FILES: usize = 32;
pub(crate) const MAX_PICKER_NAME: usize = 64;
pub(crate) static PICKER_ACTIVE: AtomicBool = AtomicBool::new(false);
pub(crate) static PICKER_SELECTED: AtomicUsize = AtomicUsize::new(0);
pub(crate) static PICKER_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(crate) static mut PICKER_FILES: [[u8; MAX_PICKER_NAME]; MAX_PICKER_FILES] =
    [[0u8; MAX_PICKER_NAME]; MAX_PICKER_FILES];
pub(crate) static mut PICKER_LENS: [usize; MAX_PICKER_FILES] = [0usize; MAX_PICKER_FILES];
pub(crate) static mut PICKER_IS_DIR: [bool; MAX_PICKER_FILES] = [false; MAX_PICKER_FILES];
pub(crate) static mut PICKER_PATH: [u8; PATH_SIZE] = [0u8; PATH_SIZE];
pub(crate) static PICKER_PATH_LEN: AtomicUsize = AtomicUsize::new(0);

pub(crate) static PICKER_SAVE_MODE: AtomicBool = AtomicBool::new(false);
pub(crate) const MAX_FILENAME_LEN: usize = 64;
pub(crate) static mut SAVE_FILENAME: [u8; MAX_FILENAME_LEN] = [0u8; MAX_FILENAME_LEN];
pub(crate) static SAVE_FILENAME_LEN: AtomicUsize = AtomicUsize::new(0);

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
