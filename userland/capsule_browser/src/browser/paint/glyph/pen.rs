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

    pub fn len(&self, u: i32) -> i32 {
        u * self.size / 48
    }

    pub fn weight(&self) -> u32 {
        self.t as u32
    }

    pub fn line(&self, fb: &mut PaintBuffer, a: (i32, i32), b: (i32, i32)) {
        let (x0, y0) = self.p(a.0, a.1);
        let (x1, y1) = self.p(b.0, b.1);
        let flat = (x1 - x0).abs() >= (y1 - y0).abs();
        for k in 0..self.t {
            let o = k - self.t / 2;
            let (dx, dy) = if flat { (0, o) } else { (o, 0) };
            fb.line_aa(x0 + dx, y0 + dy, x1 + dx, y1 + dy, self.argb);
        }
    }

    pub fn poly(&self, fb: &mut PaintBuffer, pts: &[(i32, i32)]) {
        for w in pts.windows(2) {
            self.line(fb, w[0], w[1]);
        }
    }
}
