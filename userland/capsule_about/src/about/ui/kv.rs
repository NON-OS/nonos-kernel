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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left, truncate};

use super::metrics::{BODY_PX, KV_GAP, KV_LABEL_W, KV_ROW_H, NUM_PX, PAIR_LINE};
use super::mono::{mono, truncate_mono, valid};

pub const ROW_H: u32 = KV_ROW_H;

// A label/value pair on one baseline. The label column is fixed so a stack of
// rows reads as a table without drawing one; the value is measured and cut to
// what is left, never by glyph count, because the body face is proportional.
// Numeric and hash-like values go through the mono face so digits align down
// the column. The row is placed in i32 so one that has left the pane simply does
// not land rather than being clamped to its top edge.
pub fn kv(fb: &mut PaintBuffer, x: u32, y: i32, w: u32, label: &[u8], value: &[u8], num: bool) {
    let r = roles();
    let top = y + centre_top(0, KV_ROW_H, BODY_PX);
    let label_w = KV_LABEL_W.min(w);
    let cut = truncate(valid(label), label_w.saturating_sub(KV_GAP), BODY_PX);
    left(fb, x, top, &cut, r.muted, BODY_PX);
    let value_x = x + label_w;
    let value_w = w.saturating_sub(label_w);
    if num {
        let cut = truncate_mono(value, value_w, NUM_PX);
        mono(fb, value_x, top, cut.as_bytes(), r.text_2, NUM_PX);
        return;
    }
    let cut = truncate(valid(value), value_w, BODY_PX);
    left(fb, value_x, top, &cut, r.text_2, BODY_PX);
}

// A label over its value. Long values that would be cut to nothing in a kv row's
// share of a narrow card get the card's whole width here instead.
pub fn pair(fb: &mut PaintBuffer, x: u32, y: i32, w: u32, label: &[u8], value: &[u8], num: bool) {
    let r = roles();
    let cut = truncate(valid(label), w, BODY_PX);
    left(fb, x, y, &cut, r.muted, BODY_PX);
    let vy = y + PAIR_LINE as i32;
    if num {
        let cut = truncate_mono(value, w, NUM_PX);
        mono(fb, x, vy, cut.as_bytes(), r.text_2, NUM_PX);
        return;
    }
    let cut = truncate(valid(value), w, BODY_PX);
    left(fb, x, vy, &cut, r.text_2, BODY_PX);
}
