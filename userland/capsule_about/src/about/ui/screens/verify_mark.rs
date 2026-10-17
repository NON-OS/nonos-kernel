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

//! The verdict glyphs.
//!
//! Three shapes, not three colours. Colour is the fastest signal and the least
//! reliable one: it is gone for a colour-blind reader and gone again in a
//! screenshot that has been through a filter, and this is the screen where being
//! misread matters most.

use nonos_app_skeleton::PaintBuffer;

use crate::about::data::verify::Verdict;

use super::super::kv::ROW_H;
use super::verify_glyph::{cross, tick};
use super::verify_row::tint;

pub(super) const MARK: u32 = 11;
pub(super) const STROKE: u32 = 2;

// Three shapes, not three colours: a tick that holds, a cross that does not, and
// a dash for a question the kernel would not answer. Drawn from rects because
// the toolkit has no vector path and a font glyph would sit on the text baseline
// rather than on the row's own centre.
pub(super) fn mark(fb: &mut PaintBuffer, x: u32, y: i32, v: Verdict) {
    let cy = y + (ROW_H / 2) as i32;
    if cy < 0 || cy >= fb.height as i32 {
        return;
    }
    let cy = cy as u32;
    let argb = tint(v).argb();
    match v {
        Verdict::Holds => tick(fb, x, cy, argb),
        Verdict::Broken => cross(fb, x, cy, argb),
        Verdict::Unknown => {
            fb.fill_rect(x + 1, cy.saturating_sub(STROKE / 2), MARK - 2, STROKE, argb);
        }
    }
}
