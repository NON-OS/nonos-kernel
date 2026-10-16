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
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use super::chrome_glow::glow_out;
use super::layout::R_CARD;

/// A raised plate: rounded fill, 1px hairline, optional vertical tint, optional
/// outer glow. The hairline starts as the theme's border.
#[derive(Clone, Copy)]
pub struct Plate {
    fill: u32,
    line: u32,
    r: u32,
    tint: bool,
    glow: u32,
}

impl Plate {
    pub fn new(fill: u32) -> Self {
        Self { fill, line: roles().border.argb(), r: R_CARD, tint: false, glow: 0 }
    }

    pub const fn radius(mut self, r: u32) -> Self {
        self.r = r;
        self
    }

    pub const fn line(mut self, line: u32) -> Self {
        self.line = line;
        self
    }

    /// A lift of the theme's ink over the plate, strongest at the top.
    pub const fn tint(mut self) -> Self {
        self.tint = true;
        self
    }

    pub const fn glow(mut self, spread: u32) -> Self {
        self.glow = spread;
        self
    }

    /// Blends throughout, so a plate is safe over live paint. The tint ramps
    /// across the straight rows only; a rect gradient would square the corners.
    pub fn draw(&self, fb: &mut PaintBuffer, x: u32, y: u32, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        if self.glow > 0 {
            glow_out(fb, x, y, w, h, self.r, self.glow);
        }
        fb.fill_round(x, y, w, h, self.r, self.fill);
        if self.tint {
            let (cap, ink) = (self.r.min(h / 2), roles().text.argb());
            if h > cap * 2 {
                let (top, bottom) = (with_alpha(ink, 0x16), with_alpha(ink, 0x04));
                fb.gradient_v(x, y + cap, w, h - cap * 2, top, bottom);
            }
        }
        fb.stroke_round(x, y, w, h, self.r, 1, self.line);
    }
}
