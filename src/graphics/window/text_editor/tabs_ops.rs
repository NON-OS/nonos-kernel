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

use super::tabs_state::{TabBuffer, ACTIVE_TAB, MAX_TABS, TABS, TAB_COUNT};
use core::sync::atomic::Ordering;

pub fn switch_tab(idx: usize) {
    if idx < TAB_COUNT.load(Ordering::Relaxed) {
        super::tabs_sync::save_current_to_tab();
        ACTIVE_TAB.store(idx, Ordering::Relaxed);
        super::tabs_sync::load_tab_to_current();
    }
}

pub fn new_tab() -> bool {
    let count = TAB_COUNT.load(Ordering::Relaxed);
    if count >= MAX_TABS {
        return false;
    }
    super::tabs_sync::save_current_to_tab();
    unsafe {
        TABS[count] = TabBuffer::new();
        TABS[count].active = true;
    }
    TAB_COUNT.store(count + 1, Ordering::Relaxed);
    ACTIVE_TAB.store(count, Ordering::Relaxed);
    super::file::new_file();
    true
}

pub fn close_tab(idx: usize) -> bool {
    let count = TAB_COUNT.load(Ordering::Relaxed);
    if count <= 1 || idx >= count {
        return false;
    }
    unsafe {
        for i in idx..count - 1 {
            TABS[i] = core::mem::replace(&mut TABS[i + 1], TabBuffer::new());
        }
        TABS[count - 1].active = false;
    }
    TAB_COUNT.store(count - 1, Ordering::Relaxed);
    let active = ACTIVE_TAB.load(Ordering::Relaxed);
    if active >= count - 1 {
        ACTIVE_TAB.store(count - 2, Ordering::Relaxed);
    }
    super::tabs_sync::load_tab_to_current();
    true
}

pub fn get_tab_name(idx: usize) -> &'static [u8] {
    unsafe {
        if idx < MAX_TABS && TABS[idx].path_len > 0 {
            &TABS[idx].path[..TABS[idx].path_len]
        } else {
            b"untitled"
        }
    }
}

pub fn is_tab_modified(idx: usize) -> bool {
    unsafe { idx < MAX_TABS && TABS[idx].modified }
}
