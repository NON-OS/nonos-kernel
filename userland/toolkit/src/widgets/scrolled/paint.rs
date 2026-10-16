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

//! Each primitive moved up by the scroll and cut to the buffer.

use super::Scrolled;
use crate::icons::IconId;
use crate::widgets::surface::Surface;

impl Surface for Scrolled<'_, '_> {
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.fill_rect(x, y, w, h, argb);
    }

    fn blend_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.blend_rect(x, y, w, h, argb);
    }

    fn fill_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.fill_round(x, y, w, h, r.min(h / 2), argb);
    }

    fn stroke_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, t: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.stroke_round(x, y, w, h, r.min(h / 2), t, argb);
    }

    fn circle(&mut self, cx: u32, cy: u32, r: u32, argb: u32) {
        let d = r.saturating_mul(2);
        self.fill_round(cx.saturating_sub(r), cy.saturating_sub(r), d, d, r, argb);
    }

    fn text_ttf(&mut self, x: i32, top_y: i32, text: &str, argb: u32, px: f32) -> i32 {
        self.fb.text_ttf(x, top_y.saturating_sub_unsigned(self.scroll), text, argb, px)
    }

    /// Draws the icon only when its whole `size` square is on screen. An icon
    /// blends a raw mask that cannot be cut, so one partly scrolled off the
    /// top or bottom is skipped rather than drawn in the wrong place.
    fn icon(&mut self, id: IconId, x: u32, y: u32, size: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, size) else { return };
        if h == size {
            crate::icons::draw(self.fb, id, x, y, size, argb);
        }
    }
}
