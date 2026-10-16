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

//! A `Surface` that paints all but one mark, so a widget drawn through it
//! and drawn plainly differ only in that mark, and every other pixel, the
//! ground under the mark among them, is the same.

use nonos_toolkit::icons::IconId;
use nonos_toolkit::paint::{measure_ttf, PaintBuffer};
use nonos_toolkit::widgets::Surface;

use super::hide::Hide;

/// A buffer that paints everything but what `hide` names.
pub(crate) struct Masked<'s, 'b> {
    pub(crate) fb: &'s mut PaintBuffer<'b>,
    pub(crate) hide: Hide,
    pub(crate) rounds: u32,
}

impl Surface for Masked<'_, '_> {
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        self.fb.fill_rect(x, y, w, h, argb);
    }
    fn blend_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        self.fb.blend_rect(x, y, w, h, argb);
    }
    fn fill_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, argb: u32) {
        let n = self.rounds;
        self.rounds += 1;
        if !matches!(self.hide, Hide::Round(k) if k == n) {
            self.fb.fill_round(x, y, w, h, r, argb);
        }
    }
    fn stroke_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, t: u32, argb: u32) {
        self.fb.stroke_round(x, y, w, h, r, t, argb);
    }
    fn circle(&mut self, cx: u32, cy: u32, r: u32, argb: u32) {
        if !matches!(self.hide, Hide::Dots) {
            self.fb.circle(cx, cy, r, argb);
        }
    }
    fn text_ttf(&mut self, x: i32, top: i32, text: &str, argb: u32, px: f32) -> i32 {
        if self.hide.text(text) {
            return x + measure_ttf(text, px);
        }
        self.fb.text_ttf(x, top, text, argb, px)
    }
    fn icon(&mut self, id: IconId, x: u32, y: u32, size: u32, argb: u32) {
        if !matches!(self.hide, Hide::Icons) {
            Surface::icon(self.fb, id, x, y, size, argb);
        }
    }
}
