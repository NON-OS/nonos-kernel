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

use super::pen::Pen;
use super::stroke::{self, SUB};

const STEPS: u64 = 64;
const COS: i64 = 65220;
const SIN: i64 = 6424;

/* The round and framed shapes a pen strokes, on the same design grid. */
impl Pen {
    pub fn ring(&self, fb: &mut PaintBuffer, u: i32, v: i32, r: i32) {
        let (x, y) = self.p(u, v);
        let r = (self.len(r) + self.t / 2).max(1) as u32;
        fb.ring(x.max(0) as u32, y.max(0) as u32, r, self.weight(), self.argb);
    }

    pub fn frame(&self, fb: &mut PaintBuffer, a: (i32, i32), b: (i32, i32), r: i32) {
        let (x0, y0) = self.p(a.0, a.1);
        let (x1, y1) = self.p(b.0, b.1);
        let (w, h) = ((x1 - x0).max(1) as u32, (y1 - y0).max(1) as u32);
        let r = self.len(r).max(1) as u32;
        fb.stroke_round(x0.max(0) as u32, y0.max(0) as u32, w, h, r, self.weight(), self.argb);
    }

    /// `num / den` of a turn clockwise from twelve o'clock, as a path of
    /// `STEPS`-to-the-turn chords, each turned from the last by the 16.16
    /// cosine and sine of one step.
    pub fn arc(&self, fb: &mut PaintBuffer, r: i32, num: u64, den: u64) {
        let n = (STEPS * num.min(den) / den.max(1)) as usize;
        let (cx, cy) = self.q(24, 24);
        let (mut dx, mut dy) = (0i64, -(r as i64) * self.len(48) as i64 * SUB / 48);
        let mut pts = [(0i64, 0i64); STEPS as usize + 1];
        for slot in pts.iter_mut().take(n + 1) {
            *slot = (cx + dx, cy + dy);
            (dx, dy) = ((dx * COS - dy * SIN) >> 16, (dx * SIN + dy * COS) >> 16);
        }
        stroke::path(fb, &pts[..n + 1], self.half(), self.argb);
    }
}
