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

//! An open select's list, drawn over the page by the browser itself
//! (event::select_list holds what it shows and where).

use nonos_app_skeleton::PaintBuffer;

use crate::browser::event::select_list::ROW_H;
use crate::browser::event::{select_placed, SELECT_PX};
use crate::browser::state::State;

const BG: u32 = 0xFFFF_FFFF;
const EDGE: u32 = 0xFF8A_8F98;
const FG: u32 = 0xFF1F_2328;
const OFF: u32 = 0xFF9A_A0A6;
const HEAD: u32 = 0xFF5F_6368;
const HI_BG: u32 = 0xFF2B_6CB0;
const HI_FG: u32 = 0xFFFF_FFFF;
const PAD: i32 = 8;

/// Draw the open list, if there is one, over whatever the page drew.
pub fn paint(state: &State, fb: &mut PaintBuffer) {
    let (Some(list), Some(at)) = (state.ui.select.as_ref(), select_placed(state)) else {
        return;
    };
    let bottom = fb.height as i32;
    let (x, w) = (at.x.max(0) as u32, at.w.min(fb.width));
    let y0 = at.y;
    let (vis0, vis1) = (y0.max(0), (y0 + at.h as i32).min(bottom));
    if vis1 <= vis0 {
        return;
    }
    fb.fill_rect(x, vis0 as u32, w, (vis1 - vis0) as u32, EDGE);
    for (n, row) in list.rows.iter().enumerate().skip(list.first).take(list.shown()) {
        let ry = y0 + 1 + ((n - list.first) as u32 * ROW_H) as i32;
        if ry < 0 || ry + ROW_H as i32 > bottom {
            continue;
        }
        let hi = n == list.hi && row.choosable();
        let bg = if hi { HI_BG } else { BG };
        fb.fill_rect(x + 1, ry as u32, w.saturating_sub(2), ROW_H, bg);
        let fg = match (hi, row.heading, row.disabled) {
            (true, _, _) => HI_FG,
            (_, true, _) => HEAD,
            (_, _, true) => OFF,
            _ => FG,
        };
        /* A chosen option carries a mark at its left; an option under a
         * heading sits in from it. */
        if row.selected {
            fb.fill_rect(x + 4, (ry + ROW_H as i32 / 2 - 2) as u32, 4, 4, fg);
        }
        let indent = if row.heading { 0 } else { 4 };
        let mut cell =
            fb.sub(x + (PAD + indent) as u32, ry as u32, w.saturating_sub(2 * PAD as u32), ROW_H);
        cell.text_ttf(0, 4, &row.label, fg, SELECT_PX);
    }
}
