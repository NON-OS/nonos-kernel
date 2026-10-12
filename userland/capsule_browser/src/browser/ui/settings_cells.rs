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

use alloc::vec::Vec;

use super::rect::Rect;
use super::settings_rows::{Control, Field, Item, Kind, Line};

pub const GAP: i32 = 8;
pub const CTL_H: i32 = 36;
const HINT_H: i32 = 28;
const BTN_W: i32 = 88;
const SIZE_W: i32 = 240;

pub fn push_ctl(out: &mut Vec<Item>, c: Control, rect: Rect) {
    out.push(Item { kind: Kind::Ctl(c), rect });
}

/// A field filling the band `ctl` left of its buttons `cs`, with the line
/// `hint` under it.
pub fn field_row(out: &mut Vec<Item>, ctl: Rect, f: Field, cs: &[Control], hint: Line) {
    let n = cs.len() as i32;
    let bw = BTN_W.min(ctl.w / (n + 2));
    let fw = (ctl.w - n * (bw + GAP)).max(0);
    push_ctl(out, Control::Field(f), Rect::new(ctl.x, ctl.y, fw, CTL_H));
    for (i, c) in cs.iter().enumerate() {
        let x = ctl.x + fw + GAP + i as i32 * (bw + GAP);
        push_ctl(out, *c, Rect::new(x, ctl.y, bw, CTL_H));
    }
    let line = Rect::new(ctl.x, ctl.bottom() + 2, ctl.w, HINT_H);
    out.push(Item { kind: Kind::Line(hint), rect: line });
}

/// Smaller and Larger at either end of the band `ctl`, the size dots
/// between them.
pub fn size_row(out: &mut Vec<Item>, ctl: Rect) {
    let span = SIZE_W.min(ctl.w).max(2 * CTL_H);
    let dots_w = (span - 2 * (CTL_H + GAP)).max(0);
    push_ctl(out, Control::Smaller, Rect::new(ctl.x, ctl.y, CTL_H, CTL_H));
    let dots = Rect::new(ctl.x + CTL_H + GAP, ctl.y, dots_w, CTL_H);
    out.push(Item { kind: Kind::Line(Line::SizeDots), rect: dots });
    push_ctl(out, Control::Larger, Rect::new(ctl.x + span - CTL_H, ctl.y, CTL_H, CTL_H));
}
