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

//! The window ground: panel fill, the two ambient radials and the circuit
//! grid. Section 01 calls these part of the ground rather than decoration, so
//! they are baked once into a cache the size of the surface and copied in at
//! the head of every frame. Recomputing two elliptical radials per frame would
//! cost more than the rest of the paint put together.

extern crate alloc;

use alloc::vec::Vec;
use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::{mix, opaque};
use nonos_toolkit::theme::roles;

const GRID: i32 = 46;

pub struct Ground {
    w: i32,
    h: i32,
    seeds: [u32; 3],
    px: Vec<u32>,
}

/// The roles the ground is baked from, so a theme change rebuilds it.
fn seeds() -> [u32; 3] {
    let r = roles();
    [r.bg.argb(), r.surface.argb(), r.accent.argb()]
}

/// `tint` over `base` inside the ellipse of radii `rx` by `ry`, strongest at
/// its centre, where it reaches `peak` percent, and gone at its rim.
pub(crate) fn radial(base: u32, tint: u32, dx: i64, dy: i64, rx: i64, ry: i64, peak: u32) -> u32 {
    let d = (dx * dx * 10_000 / (rx * rx)) + (dy * dy * 10_000 / (ry * ry));
    if d >= 10_000 {
        return base;
    }
    let fall = (10_000 - d) as u64;
    mix(base, tint, (fall * peak as u64 * 255 / 10_000 / 100).min(255) as u8)
}

impl Ground {
    pub fn build(w: i32, h: i32) -> Ground {
        let mut px = Vec::with_capacity((w * h).max(0) as usize);
        let seeds @ [bg, surface, accent] = seeds();
        for y in 0..h {
            for x in 0..w {
                let mut c = mix(bg, surface, (y * 255 / h.max(1)) as u8);
                c = radial(c, accent, (x - w / 2) as i64, (y + h / 10) as i64, 550, 310, 16);
                c = radial(c, accent, (x - w * 88 / 100) as i64, (y - h * 108 / 100) as i64, 380, 260, 14);
                if x % GRID == 0 || y % GRID == 0 {
                    c = mix(c, accent, 5);
                }
                px.push(opaque(c));
            }
        }
        Ground { w, h, seeds, px }
    }

    pub fn fits(&self, w: u32, h: u32) -> bool {
        self.w == w as i32 && self.h == h as i32 && self.seeds == seeds()
    }

    pub fn blit(&self, fb: &mut PaintBuffer) {
        let stride = fb.stride_words as usize;
        let w = (self.w as usize).min(fb.width as usize);
        for y in 0..(self.h as usize).min(fb.height as usize) {
            let dst = y * stride;
            let src = y * self.w as usize;
            if dst + w <= fb.pixels.len() {
                fb.pixels[dst..dst + w].copy_from_slice(&self.px[src..src + w]);
            }
        }
    }
}
