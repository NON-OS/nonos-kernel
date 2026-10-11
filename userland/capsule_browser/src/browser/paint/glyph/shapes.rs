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

/* The round and framed shapes a pen strokes, on the same design grid. */
impl Pen {
    pub fn ring(&self, fb: &mut PaintBuffer, u: i32, v: i32, r: i32) {
        let (x, y) = self.p(u, v);
        let r = (self.len(r) + self.t / 2).max(1) as u32;
        fb.ring(x.max(0) as u32, y.max(0) as u32, r, self.weight(), self.argb);
    }

    pub fn dot(&self, fb: &mut PaintBuffer, u: i32, v: i32, r: i32) {
        let (x, y) = self.p(u, v);
        let r = self.len(r).max(1) as u32;
        fb.circle(x.max(0) as u32, y.max(0) as u32, r, self.argb);
    }

    pub fn frame(&self, fb: &mut PaintBuffer, a: (i32, i32), b: (i32, i32), r: i32) {
        let (x0, y0) = self.p(a.0, a.1);
        let (x1, y1) = self.p(b.0, b.1);
        let (w, h) = ((x1 - x0).max(1) as u32, (y1 - y0).max(1) as u32);
        let r = self.len(r).max(1) as u32;
        fb.stroke_round(x0.max(0) as u32, y0.max(0) as u32, w, h, r, self.weight(), self.argb);
    }

    pub fn arc(&self, fb: &mut PaintBuffer, r: i32, num: u64, den: u64) {
        let r = (self.len(r) + self.t / 2).max(1) as u32;
        let (x, y) = (self.cx.max(0) as u32, self.cy.max(0) as u32);
        fb.ring_arc(x, y, r, self.weight(), num, den, self.argb);
    }
}
