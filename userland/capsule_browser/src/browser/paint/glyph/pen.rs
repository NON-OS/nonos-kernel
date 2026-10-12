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

use super::stroke::{self, SUB};

const MAX_PTS: usize = 64;

/// Maps a 48-unit design grid centred on `(cx, cy)` onto `size` pixels and
/// strokes it at a weight that grows with the size.
pub struct Pen {
    pub(super) cx: i32,
    pub(super) cy: i32,
    size: i32,
    pub(super) t: i32,
    pub argb: u32,
}

impl Pen {
    pub fn new(cx: i32, cy: i32, size: i32, argb: u32) -> Pen {
        let size = size.max(1);
        Pen { cx, cy, size, t: ((size + 6) / 12).max(1), argb }
    }

    pub fn p(&self, u: i32, v: i32) -> (i32, i32) {
        (self.cx + (u - 24) * self.size / 48, self.cy + (v - 24) * self.size / 48)
    }

    /// Design point `(u, v)` in `stroke::SUB` units, at the pixel centre `p`
    /// would round it to but keeping the fraction it drops.
    pub fn q(&self, u: i32, v: i32) -> (i64, i64) {
        let at = |c: i32, d: i32| {
            c as i64 * SUB + SUB / 2 + (d - 24) as i64 * self.size as i64 * SUB / 48
        };
        (at(self.cx, u), at(self.cy, v))
    }

    pub fn half(&self) -> i64 {
        self.t as i64 * SUB / 2
    }

    pub fn len(&self, u: i32) -> i32 {
        u * self.size / 48
    }

    pub fn weight(&self) -> u32 {
        self.t as u32
    }

    pub fn line(&self, fb: &mut PaintBuffer, a: (i32, i32), b: (i32, i32)) {
        self.poly(fb, &[a, b]);
    }

    pub fn poly(&self, fb: &mut PaintBuffer, pts: &[(i32, i32)]) {
        let mut at = [(0i64, 0i64); MAX_PTS];
        let n = pts.len().min(MAX_PTS);
        for (slot, &(u, v)) in at.iter_mut().zip(&pts[..n]) {
            *slot = self.q(u, v);
        }
        stroke::path(fb, &at[..n], self.half(), self.argb);
    }
}
