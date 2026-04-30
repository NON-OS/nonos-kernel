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

use super::buffer::{delete_selection, insert_str};
use super::state::*;
use core::sync::atomic::Ordering;

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
    let selected = unsafe { &EDITOR_BUFFER[sel_start..sel_end] };

    crate::graphics::clipboard::copy_text(selected);
    EDITOR_STATUS.store(STATUS_NONE, Ordering::Relaxed);
    true
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

    match crate::graphics::clipboard::get_text() {
        Some(text) => {
            insert_str(text);
            true
        }
        None => false,
    }
}
