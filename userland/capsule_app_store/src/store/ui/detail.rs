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
//! The selected listing: what it is, who stands behind it, and whether this
//! machine will run it.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{text, Card, Rect};

use super::bytes::as_str;
use super::hex::short;
use super::metrics::{BODY_PX, DETAIL_PAD, SMALL_PX, TITLE_PX};
use super::wrap::wrap;
use crate::store::state::State;

pub fn paint(state: &State, fb: &mut PaintBuffer, x: u32, y: u32, w: u32, h: u32) {
    let r = roles();
    Card::new().draw(fb, Rect { x, y, w, h });
    let left = x + DETAIL_PAD;
    let room = w.saturating_sub(DETAIL_PAD * 2);
    let Some(listing) = state.current() else {
        text::left(fb, left, y as i32 + DETAIL_PAD as i32, "Nothing selected", r.muted, BODY_PX);
        return;
    };
    let mut top = y as i32 + DETAIL_PAD as i32;
    text::left(fb, left, top, as_str(&listing.name), r.text, TITLE_PX);
    top += 32;

    if let Some(d) = &listing.known.detail {
        text::left(fb, left, top, as_str(&d.publisher), r.accent, SMALL_PX);
        top += 22;
        /*
         * Which version, before anything else. Where the bytes come from is
         * provenance the install checks, not a label.
         */
        if let Some(rel) = &listing.known.release {
            let mut line = b"Version ".to_vec();
            line.extend_from_slice(rel.short_version());
            text::left(fb, left, top, as_str(&line), r.muted, SMALL_PX);
            top += 20;
        }
        top += 6;
        for line in wrap(&d.description, room, SMALL_PX).iter().take(4) {
            text::left(fb, left, top, as_str(line), r.text_2, SMALL_PX);
            top += 20;
        }
        top += 10;
    }

    top = super::standing::paint(fb, state, left, room, top);
    if let Some(rel) = listing.known.release.as_ref().filter(|rel| !rel.note.is_empty()) {
        text::left(fb, left, top, as_str(&rel.note), r.muted, SMALL_PX);
        top += 24;
    }
    /* One line, so it stays inside the pane under a failure sentence and a note. */
    let mut line = b"measurement  ".to_vec();
    line.extend_from_slice(&short(&listing.measurement));
    text::left(fb, left, top, as_str(&line), r.muted, SMALL_PX);
}
