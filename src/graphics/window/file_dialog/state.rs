// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::entries::refresh_entries;
use super::path::{get_filename, get_path, set_path};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

pub(super) const MAX_ENTRIES: usize = 64;
pub(super) const MAX_NAME: usize = 64;

#[derive(Clone, Copy)]
pub(super) struct DirEntry {
    pub name: [u8; MAX_NAME],
    pub name_len: usize,
    pub is_dir: bool,
    pub size: u64,
}

impl DirEntry {
    pub(super) const fn empty() -> Self {
        Self { name: [0u8; MAX_NAME], name_len: 0, is_dir: false, size: 0 }
    }
}

pub(super) static ENTRY_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(super) static mut ENTRIES: [DirEntry; MAX_ENTRIES] = [DirEntry::empty(); MAX_ENTRIES];

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DialogMode {
    Open = 0,
    Save = 1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DialogResult {
    None = 0,
    Selected = 1,
    Cancelled = 2,
}

static IS_OPEN: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU8 = AtomicU8::new(0);
static RESULT: AtomicU8 = AtomicU8::new(0);

pub fn is_open() -> bool {
    IS_OPEN.load(Ordering::Relaxed)
}

pub(super) fn get_mode() -> DialogMode {
    match MODE.load(Ordering::Relaxed) {
        1 => DialogMode::Save,
        _ => DialogMode::Open,
    }
}

pub fn get_result() -> DialogResult {
    match RESULT.load(Ordering::Relaxed) {
        1 => DialogResult::Selected,
        2 => DialogResult::Cancelled,
        _ => DialogResult::None,
    }
}

pub(super) fn set_result(result: DialogResult) {
    RESULT.store(result as u8, Ordering::Relaxed);
}

pub fn open_dialog(mode: DialogMode, initial_path: &[u8]) {
    IS_OPEN.store(true, Ordering::Relaxed);
    MODE.store(mode as u8, Ordering::Relaxed);
    RESULT.store(0, Ordering::Relaxed);
    set_path(initial_path);
    refresh_entries(initial_path);
}

pub fn close_dialog() {
    IS_OPEN.store(false, Ordering::Relaxed);
}

pub fn get_selected_path() -> (&'static [u8], &'static [u8]) {
    (get_path(), get_filename())
}
