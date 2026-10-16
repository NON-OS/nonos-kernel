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

//! A pixel buffer larger than the box a widget is given, so every pixel the
//! widget changes can be found and placed.

use nonos_toolkit::paint::PaintBuffer;
use nonos_toolkit::widgets::Rect;

/// The room left round the box on every side.
pub(crate) const MARGIN: u32 = 24;

/// Pixels in rows of `w`, `h` rows deep.
#[derive(Clone)]
pub(crate) struct Canvas {
    pub(crate) px: Vec<u32>,
    pub(crate) w: u32,
    pub(crate) h: u32,
}

impl Canvas {
    /// A canvas holding `at` with `MARGIN` past its far edges, every pixel `fill`.
    pub(crate) fn new(at: Rect, fill: u32) -> Self {
        let (w, h) = (at.x + at.w + MARGIN, at.y + at.h + MARGIN);
        Canvas { px: vec![fill; (w * h) as usize], w, h }
    }

    /// The canvas after `draw` has painted on it through a `PaintBuffer`.
    pub(crate) fn painted(mut self, draw: impl FnOnce(&mut PaintBuffer<'_>)) -> Self {
        let (w, h) = (self.w, self.h);
        let mut fb = PaintBuffer { pixels: &mut self.px, stride_words: w, width: w, height: h };
        draw(&mut fb);
        self
    }

    /// The pixel at `x`, `y`.
    pub(crate) fn get(&self, x: u32, y: u32) -> u32 {
        self.px[(y * self.w + x) as usize]
    }

    /// Every point whose pixel differs from the same point of `other`.
    pub(crate) fn diff(&self, other: &Canvas) -> Vec<(u32, u32)> {
        let w = self.w;
        let pairs = self.px.iter().zip(&other.px).enumerate();
        pairs.filter(|(_, (a, b))| a != b).map(|(i, _)| (i as u32 % w, i as u32 / w)).collect()
    }

    /// Every point whose pixel is no longer `fill`.
    pub(crate) fn changed(&self, fill: u32) -> Vec<(u32, u32)> {
        let w = self.w;
        let all = self.px.iter().enumerate();
        all.filter(|(_, p)| **p != fill).map(|(i, _)| (i as u32 % w, i as u32 / w)).collect()
    }
}
