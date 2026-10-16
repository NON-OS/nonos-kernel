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

//! The claims this window cannot settle, and why.
//!
//! This is the card that makes the other two worth reading. A verification
//! surface that lists only what it can prove is telling you a selected truth: the
//! reader has no way to know what was left out, and every system's About box
//! looks complete for exactly that reason.
//!
//! So the claims that cannot be tested from here are named, each with the reason
//! it is out of reach and the place it is actually settled. Two of them are out
//! of reach precisely because this capsule is confined, which is the system
//! working rather than failing.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::super::card::{self, titled};
use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, CARD_PAD};
use super::super::text::{fit, line, top_of};
use super::prose;
use super::verify_items::ITEMS;

const ITEM_GAP: u32 = 8;

pub fn height(inner: u32) -> u32 {
    let body = inner.saturating_sub(CARD_PAD);
    let mut h = card::OVERHEAD + ROW_H;
    for (claim, why) in ITEMS {
        let _ = claim;
        h += ROW_H + prose::height(why, body) + ITEM_GAP;
    }
    h
}

pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32) {
    let r = roles();
    let inner = card::inner(w);
    let top = titled(fb, 0, y, w, height(inner), b"Not checkable from here");
    let note = b"Named rather than omitted, so this list is not a selected truth.";
    line(fb, CARD_PAD, top_of(top, ROW_H, BODY_PX), note, r.muted.argb(), BODY_PX);

    let body = inner.saturating_sub(CARD_PAD);
    let mut row_y = top + ROW_H as i32;
    for (claim, why) in ITEMS {
        let cut = fit(fb, claim, BODY_PX, inner);
        line(fb, CARD_PAD, top_of(row_y, ROW_H, BODY_PX), cut, r.text_2.argb(), BODY_PX);
        let why_y = row_y + ROW_H as i32;
        prose::paint(fb, CARD_PAD + CARD_PAD, why_y, body, why, r.muted.argb());
        row_y = why_y + (prose::height(why, body) + ITEM_GAP) as i32;
    }
}
