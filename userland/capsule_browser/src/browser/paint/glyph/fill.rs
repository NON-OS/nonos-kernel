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
use super::stroke::SUB;

const MAX_CROSS: usize = 16;

/// Even-odd scanline fill of a closed design-grid polygon, sampled at pixel
/// centres on the same sub-pixel points the outline is stroked through, so
/// the fill meets the stroke's inner edge. The caller strokes the outline on
/// top to anti-alias the edge.
pub fn fill_polygon(fb: &mut PaintBuffer, p: &Pen, pts: &[(i32, i32)]) {
    let mut px = [(0i64, 0i64); MAX_CROSS];
    let n = pts.len().min(MAX_CROSS);
    for i in 0..n {
        px[i] = p.q(pts[i].0, pts[i].1);
    }
    let top = px[..n].iter().map(|q| q.1).min().unwrap_or(0) / SUB;
    let bottom = px[..n].iter().map(|q| q.1).max().unwrap_or(0) / SUB;
    for y in top.max(0)..=bottom {
        let sy = y * SUB + SUB / 2;
        let mut xs = [0i64; MAX_CROSS];
        let mut k = 0;
        for i in 0..n {
            let (a, b) = (px[i], px[(i + 1) % n]);
            if (a.1 <= sy) == (b.1 <= sy) || k == MAX_CROSS {
                continue;
            }
            xs[k] = a.0 + (b.0 - a.0) * (sy - a.1) / (b.1 - a.1);
            k += 1;
        }
        xs[..k].sort_unstable();
        for pair in xs[..k].chunks(2) {
            if let [l, r] = *pair {
                let (l, r) = (((l + SUB / 2) / SUB).max(0), (r + SUB / 2) / SUB);
                if r > l {
                    fb.blend_rect(l as u32, y as u32, (r - l) as u32, 1, p.argb);
                }
            }
        }
    }
}
