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

use core::sync::atomic::Ordering;
use super::state::*;
use super::buffer::{delete_selection, insert_str};

pub(super) fn copy_selection() -> bool {
    if !EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
        return false;
    }

    let start = EDITOR_SELECTION_START.load(Ordering::Relaxed);
    let end = EDITOR_SELECTION_END.load(Ordering::Relaxed);
    let (sel_start, sel_end) = if start < end { (start, end) } else { (end, start) };
    let len = EDITOR_LEN.load(Ordering::Relaxed);

    if sel_end > len || sel_start >= sel_end {
        return false;
    }

    // SAFETY: Single-threaded buffer access
    let selected = unsafe {
        match core::str::from_utf8(&EDITOR_BUFFER[sel_start..sel_end]) {
            Ok(s) => s,
            Err(_) => return false,
        }
    };

    if crate::ui::clipboard::set_clipboard("text/plain", selected).is_ok() {
        EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
        true
    } else {
        false
    }
}

pub(super) fn cut_selection() -> bool {
    if copy_selection() {
        delete_selection();
        true
    } else {
        false
    }
}

pub(super) fn paste() -> bool {
    if EDITOR_HAS_SELECTION.load(Ordering::Relaxed) {
        delete_selection();
    }

    match crate::ui::clipboard::get_clipboard("text/plain") {
        Ok(Some(text)) => {
            insert_str(text.as_bytes());
            true
        }
        _ => false,
    }
}
