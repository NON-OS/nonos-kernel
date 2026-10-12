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

use crate::browser::omnibox::Change;
use crate::browser::state::State;

/* Fold one word into a running FNV-1a style hash. */
pub(super) fn fold(h: u64, w: u64) -> u64 {
    (h ^ w).wrapping_mul(0x0100_0000_01b3)
}

/* What of the page area the tick can change without saying so: a new
 * layout (a fresh display list), an image fetch finishing, the status text
 * shown while there is no document yet. Byte-reading fetch steps change
 * none of these, so they cost no repaint. */
fn page_print(state: &State) -> u64 {
    let mut h = fold(0xcbf2_9ce4_8422_2325, state.view as u64);
    if let Some(d) = state.box_doc.as_ref() {
        h = fold(fold(h, d.frags.as_ptr() as u64), d.frags.len() as u64);
        h = fold(h, d.content_h as u64);
    }
    if let Some(d) = state.document.as_ref() {
        h = fold(fold(h, d.lines.as_ptr() as u64), d.lines.len() as u64);
    }
    if state.box_doc.is_none() && state.document.is_none() {
        h = state.status.bytes().fold(h, |h, b| fold(h, b as u64));
    }
    let image = state.fetch.as_ref().is_some_and(|f| f.image.is_some());
    fold(fold(h, image as u64), state.image_queue.len() as u64)
}

/* The toolbar shows Stop while loading and Reload otherwise. */
fn chrome_print(state: &State) -> u64 {
    fold(state.loading() as u64, state.ui.truncated as u64)
}

pub(super) fn note_changes(state: &mut State) {
    let page = page_print(state);
    if page != state.track.page_print {
        state.track.page_print = page;
        state.mark(Change::Page);
    }
    let chrome = chrome_print(state);
    if chrome != state.track.chrome_print {
        state.track.chrome_print = chrome;
        state.mark(Change::Toolbar);
    }
}
