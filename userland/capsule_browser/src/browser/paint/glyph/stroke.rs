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

/// Sub-pixel steps per pixel that stroke points and widths are placed at.
pub const SUB: i64 = 16;

/// Strokes the open path through `pts` (in `SUB` units) `half` units either
/// side of its centre line, with round ends and joins. Each pixel is blended
/// once, by how far its centre lies from the nearest segment, so the edge is
/// anti-aliased and a join carries no doubled edge.
pub fn path(fb: &mut PaintBuffer, pts: &[(i64, i64)], half: i64, argb: u32) {
    let Some(&(fx, fy)) = pts.first() else { return };
    let (mut x0, mut y0, mut x1, mut y1) = (fx, fy, fx, fy);
    for &(x, y) in pts {
        (x0, y0, x1, y1) = (x0.min(x), y0.min(y), x1.max(x), y1.max(y));
    }
    let pad = half + SUB;
    let (px0, py0) = (((x0 - pad) / SUB).max(0), ((y0 - pad) / SUB).max(0));
    let px1 = ((x1 + pad) / SUB).min(fb.width as i64 - 1);
    let py1 = ((y1 + pad) / SUB).min(fb.height as i64 - 1);
    let (alpha, rgb) = (((argb >> 24) & 0xFF) as i64, argb & 0x00FF_FFFF);
    for py in py0..=py1 {
        for px in px0..=px1 {
            let c = (px * SUB + SUB / 2, py * SUB + SUB / 2);
            let d = isqrt(nearest(pts, c));
            let cov = (half + SUB / 2 - d).clamp(0, SUB);
            let a = (alpha * cov / SUB) as u32;
            if a > 0 {
                fb.blend_px(px as u32, py as u32, (a << 24) | rgb);
            }
        }
    }
}

fn nearest(pts: &[(i64, i64)], c: (i64, i64)) -> i64 {
    let lone = pts.first().map_or(0, |&a| segment(a, a, c));
    pts.windows(2).map(|w| segment(w[0], w[1], c)).min().unwrap_or(lone)
}

/// The squared distance from `c` to the segment `a`-`b`.
fn segment(a: (i64, i64), b: (i64, i64), c: (i64, i64)) -> i64 {
    let (abx, aby) = (b.0 - a.0, b.1 - a.1);
    let (acx, acy) = (c.0 - a.0, c.1 - a.1);
    let len2 = abx * abx + aby * aby;
    let t = if len2 == 0 { 0 } else { (acx * abx + acy * aby).clamp(0, len2) };
    let (qx, qy) =
        if len2 == 0 { (acx, acy) } else { (acx - abx * t / len2, acy - aby * t / len2) };
    qx * qx + qy * qy
}

fn isqrt(v: i64) -> i64 {
    if v <= 0 {
        return 0;
    }
    let (mut x, mut y) = (v, (v + 1) / 2);
    while y < x {
        x = y;
        y = (x + v / x) / 2;
    }
    x
}
