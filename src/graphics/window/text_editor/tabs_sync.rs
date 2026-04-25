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

use super::state::*;
use super::syntax;
use super::tabs_state::*;
use core::sync::atomic::Ordering;

pub(super) fn save_current_to_tab() {
    let idx = active_tab();
    if idx >= MAX_TABS {
        return;
    }
    unsafe {
        let tab = &mut super::tabs_state::TABS[idx];
        let len = EDITOR_LEN.load(Ordering::Relaxed).min(TAB_BUFFER_SIZE);
        tab.data[..len].copy_from_slice(&EDITOR_BUFFER[..len]);
        tab.len = len;
        tab.cursor = EDITOR_CURSOR.load(Ordering::Relaxed);
        tab.scroll_y = EDITOR_SCROLL_Y.load(Ordering::Relaxed);
        tab.modified = EDITOR_MODIFIED.load(Ordering::Relaxed);
        tab.language = syntax::get_language();
        let path_len = EDITOR_PATH_LEN.load(Ordering::Relaxed).min(TAB_PATH_SIZE);
        tab.path[..path_len].copy_from_slice(&EDITOR_FILE_PATH[..path_len]);
        tab.path_len = path_len;
    }
}

pub(super) fn load_tab_to_current() {
    let idx = active_tab();
    if idx >= MAX_TABS {
        return;
    }
    unsafe {
        let tab = &super::tabs_state::TABS[idx];
        let len = tab.len.min(BUFFER_SIZE);
        EDITOR_BUFFER[..len].copy_from_slice(&tab.data[..len]);
        EDITOR_LEN.store(len, Ordering::Relaxed);
        EDITOR_CURSOR.store(tab.cursor, Ordering::Relaxed);
        EDITOR_SCROLL_Y.store(tab.scroll_y, Ordering::Relaxed);
        EDITOR_MODIFIED.store(tab.modified, Ordering::Relaxed);
        syntax::set_language(tab.language);
        let path_len = tab.path_len.min(PATH_SIZE);
        EDITOR_FILE_PATH[..path_len].copy_from_slice(&tab.path[..path_len]);
        EDITOR_PATH_LEN.store(path_len, Ordering::Relaxed);
    }
}
