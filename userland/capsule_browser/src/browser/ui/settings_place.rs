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
use super::settings_cells::{field_row, push_ctl, size_row, CTL_H, GAP};
use super::settings_rows::{Item, Kind};
use super::settings_table::Row;

const PAD: i32 = 16;
const ROW_H: i32 = 56;
const FIELD_ROW_H: i32 = 84;
const LABEL_W: i32 = 180;
const OPT_W: i32 = 132;
const ACT_W: i32 = 300;

/// Where the next row of a card goes.
pub struct Cursor {
    pub frame: Rect,
    pub y: i32,
}

/// Lays out `row` at the cursor, pushing its label and controls, and moves
/// the cursor below it. The label takes a column at the left; the controls
/// share the band right of it, `CTL_H` tall.
pub fn place(at: &mut Cursor, row: &Row, out: &mut Vec<Item>) {
    let h = if matches!(row, Row::Field(..)) { FIELD_ROW_H } else { ROW_H };
    let inner = Rect::new(at.frame.x + PAD, at.y, (at.frame.w - 2 * PAD).max(0), h);
    let lw = LABEL_W.min(inner.w / 3);
    let y = inner.y + (ROW_H - CTL_H) / 2;
    let ctl = Rect::new(inner.x + lw + GAP, y, (inner.w - lw - GAP).max(0), CTL_H);
    let (Row::Options(s, _)
    | Row::Field(s, ..)
    | Row::Action(s, _)
    | Row::Text(s, _)
    | Row::Size(s)) = *row;
    out.push(Item { kind: Kind::Label(s), rect: Rect::new(inner.x, y, lw, CTL_H) });
    match *row {
        Row::Options(_, cs) => {
            let n = cs.len() as i32;
            let w = OPT_W.min((ctl.w - (n - 1) * GAP) / n).max(0);
            for (i, c) in cs.iter().enumerate() {
                push_ctl(out, *c, Rect::new(ctl.x + i as i32 * (w + GAP), y, w, CTL_H));
            }
        }
        Row::Field(_, f, cs, hint) => field_row(out, ctl, f, cs, hint),
        Row::Action(_, c) => push_ctl(out, c, Rect::new(ctl.x, y, ACT_W.min(ctl.w), CTL_H)),
        Row::Text(_, l) => out.push(Item { kind: Kind::Line(l), rect: ctl }),
        Row::Size(_) => size_row(out, ctl),
    }
    at.y += h;
}
