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

//! The disclosure chevron at a row's right end: a ">" built from small
//! squares, so it paints through `draw::fill` alone at any scale.

use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::paint::PaintBuffer;
use crate::theme::Opaque;
use crate::widgets::draw;

/// Fills a ">" centred in the square `at`: two strokes a double hairline
/// thick, stepped one pixel at a time, meeting at a point on the right.
pub(super) fn paint(fb: &mut PaintBuffer, at: Rect, ink: Opaque) {
    let t = scale().hair().saturating_mul(2).min(at.w);
    let reach = at.w.saturating_sub(t) / 2;
    let tall = reach.saturating_mul(2);
    let x0 = at.x.saturating_add(at.w.saturating_sub(reach.saturating_add(t)) / 2);
    let y0 = at.y.saturating_add(at.h.saturating_sub(tall.saturating_add(t)) / 2);
    for k in 0..=reach {
        let x = x0.saturating_add(k);
        draw::fill(fb, Rect { x, y: y0.saturating_add(k), w: t, h: t }, ink);
        draw::fill(fb, Rect { x, y: y0.saturating_add(tall - k), w: t, h: t }, ink);
    }
}
