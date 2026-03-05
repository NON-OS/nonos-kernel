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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) const FIND_BUFFER_SIZE: usize = 128;
pub(super) const MAX_MATCHES: usize = 256;

pub(crate) static FIND_ACTIVE: AtomicBool = AtomicBool::new(false);
pub(crate) static REPLACE_MODE: AtomicBool = AtomicBool::new(false);
pub(crate) static FIND_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static REPLACE_LEN: AtomicUsize = AtomicUsize::new(0);
pub(crate) static FIND_CURSOR: AtomicUsize = AtomicUsize::new(0);
pub(crate) static MATCH_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(crate) static CURRENT_MATCH: AtomicUsize = AtomicUsize::new(0);
pub(crate) static CASE_SENSITIVE: AtomicBool = AtomicBool::new(false);

pub(crate) static mut FIND_BUFFER: [u8; FIND_BUFFER_SIZE] = [0u8; FIND_BUFFER_SIZE];
pub(crate) static mut REPLACE_BUFFER: [u8; FIND_BUFFER_SIZE] = [0u8; FIND_BUFFER_SIZE];
pub(crate) static mut MATCH_POSITIONS: [usize; MAX_MATCHES] = [0usize; MAX_MATCHES];

pub fn open_find() {
    FIND_ACTIVE.store(true, Ordering::Relaxed);
    REPLACE_MODE.store(false, Ordering::Relaxed);
    FIND_CURSOR.store(FIND_LEN.load(Ordering::Relaxed), Ordering::Relaxed);
}

pub fn open_replace() {
    FIND_ACTIVE.store(true, Ordering::Relaxed);
    REPLACE_MODE.store(true, Ordering::Relaxed);
    FIND_CURSOR.store(FIND_LEN.load(Ordering::Relaxed), Ordering::Relaxed);
}

pub fn close_find() {
    FIND_ACTIVE.store(false, Ordering::Relaxed);
    REPLACE_MODE.store(false, Ordering::Relaxed);
    super::find_search::clear_highlights();
    super::find_input::clear_find();
    super::find_input::clear_replace();
}

pub fn is_active() -> bool {
    FIND_ACTIVE.load(Ordering::Relaxed)
}

pub(super) fn is_replace_mode() -> bool {
    REPLACE_MODE.load(Ordering::Relaxed)
}

pub fn toggle_case_sensitive() {
    let current = CASE_SENSITIVE.load(Ordering::Relaxed);
    CASE_SENSITIVE.store(!current, Ordering::Relaxed);
    if FIND_LEN.load(Ordering::Relaxed) > 0 {
        super::find_search::find_all();
    }
}

pub(super) fn _is_case_sensitive() -> bool {
    CASE_SENSITIVE.load(Ordering::Relaxed)
}

pub fn get_match_count() -> usize {
    MATCH_COUNT.load(Ordering::Relaxed)
}

pub(super) fn _get_current_match() -> usize {
    CURRENT_MATCH.load(Ordering::Relaxed)
}
