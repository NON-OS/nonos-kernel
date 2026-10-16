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

//! The grid, orb and wave motifs from section 04.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::with_alpha;

use super::curve::{contour, ellipse};
use super::rungs::rungs;
use crate::ui::geometry::Rect;
use crate::ui::paint::ring as ring_stroke;

fn pen(r: &Rect) -> i32 {
    (r.w.min(r.h) / 64).max(1)
}

pub fn grid(fb: &mut PaintBuffer, r: Rect, c: u32) {
    let s = r.w.min(r.h);
    let vy = r.y + r.h * 52 / 100;
    let vx = r.cx();
    for i in 0..=8 {
        let x = r.x - r.w / 2 + r.w * 2 * i / 8;
        let (ex, ey) = inside(r, vx, vy, x, r.bottom());
        fb.line_aa(vx, vy, ex, ey, with_alpha(c, 0x55));
    }
    for y in rungs(vy, r.bottom(), s) {
        fb.line_aa(r.x, y, r.right(), y, with_alpha(c, 0x44));
    }
    fb.line_aa(r.x, vy, r.right(), vy, c);
    fb.circle(vx as u32, vy as u32, (s * 5 / 100) as u32, with_alpha(c, 0x66));
}

pub fn orb(fb: &mut PaintBuffer, r: Rect, c: u32) {
    let s = r.w.min(r.h);
    let (cx, cy) = (r.cx(), r.y + r.h * 42 / 100);
    fb.circle(cx as u32, cy as u32, (s * 21 / 100) as u32, with_alpha(c, 0x33));
    ring_stroke(fb, cx, cy, s * 21 / 100, pen(&r) * 2, c);
    ellipse(fb, cx, cy + s * 4 / 100, s * 34 / 100, s * 10 / 100, with_alpha(c, 0xAA));
    fb.line_aa(r.x + r.w / 10, r.y + r.h * 76 / 100, r.right() - r.w / 10, r.y + r.h * 76 / 100, with_alpha(c, 0x66));
}

pub fn wave(fb: &mut PaintBuffer, r: Rect, c: u32) {
    let s = r.w.min(r.h);
    let bands = [(32i32, 14i32, 2i32, 0i32, 0xFFu8), (46, 11, 3, 40, 0xB4), (60, 8, 4, 90, 0x82), (72, 6, 5, 150, 0x55)];
    for (y, amp, cycles, phase, a) in bands {
        contour(fb, r, r.h * y / 100, s * amp / 100, cycles, phase, with_alpha(c, a));
    }
}

/// The end of the line from (x0, y0) to (x1, y1), cut where it leaves `r`'s
/// sides: the fan reaches past the cover, and drawn whole it ran across the
/// panels beside it.
fn inside(r: Rect, x0: i32, y0: i32, x1: i32, y1: i32) -> (i32, i32) {
    let edge = if x1 < r.x { r.x } else if x1 > r.right() { r.right() } else { return (x1, y1) };
    if x1 == x0 {
        return (x1, y1);
    }
    (edge, y0 + (y1 - y0) * (edge - x0) / (x1 - x0))
}
