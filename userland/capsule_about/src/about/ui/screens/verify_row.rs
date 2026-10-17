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

//! The one row shape every verdict on the screen is drawn in.
//!
//! A verdict is never colour alone. Colour is the fastest signal and the least
//! reliable one: it is gone for a colour-blind reader and gone again in a
//! screenshot that has been through a filter, and this is the screen where being
//! misread matters most. So each row carries a drawn mark whose *shape* differs,
//! the claim in words, and, on the right, the count that settled it.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::{roles, Opaque};
use nonos_toolkit::widgets::text::{centre_top, left, truncate};

use crate::about::data::verify::Verdict;

use super::super::kv::ROW_H;
use super::super::metrics::{BODY_PX, NUM_PX};
use super::super::mono::{mono, valid, width_of_mono};
use super::verify_mark::mark;

// The mark column. Wide enough for the glyph and the gap that separates it from
// the claim, so a stack of rows starts its text on one edge.
pub const MARK_W: u32 = 22;

pub fn tint(v: Verdict) -> Opaque {
    let r = roles();
    match v {
        Verdict::Holds => r.ok,
        Verdict::Broken => r.danger,
        Verdict::Unknown => r.muted,
    }
}

/// A claim, its verdict, and the evidence on the right. The evidence is passed
/// in already formatted because only the caller knows whether it is a count, a
/// hash or nothing at all.
pub fn row(fb: &mut PaintBuffer, x: u32, y: i32, w: u32, v: Verdict, claim: &[u8], ev: &[u8]) {
    let r = roles();
    let top = y + centre_top(0, ROW_H, BODY_PX);
    mark(fb, x, y, v);

    let ev_w = if ev.is_empty() { 0 } else { width_of_mono(ev, NUM_PX) };
    let text_x = x + MARK_W;
    let room = w.saturating_sub(MARK_W + ev_w + 12);
    let cut = truncate(valid(claim), room, BODY_PX);
    left(fb, text_x, top, &cut, r.text_2, BODY_PX);

    if !ev.is_empty() {
        mono(fb, x + w.saturating_sub(ev_w), top, ev, tint(v), NUM_PX);
    }
}
