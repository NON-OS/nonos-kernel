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

//! The hit proof's shared half: a widget's hit test takes every pixel it drew
//! and no point outside its box.

use nonos_toolkit::widgets::Rect;

use super::canvas::Canvas;
use super::widget::Widget;

/// The prefill drawn pixels are found against.
const GROUND: u32 = 0xFF20_2020;

/// Points just outside each corner of `at`, every fifth along each edge, and
/// far off it, negative coordinates among them.
pub(crate) fn around(at: Rect) -> Vec<(i32, i32)> {
    let (x0, y0) = (at.x as i32, at.y as i32);
    let (x1, y1) = (x0 + at.w as i32, y0 + at.h as i32);
    let mut out = vec![(-1, -1), (i32::MIN, y0), (x0, i32::MIN), (i32::MAX, i32::MAX)];
    out.extend([(x0 - 1, y0 - 1), (x1, y1), (x0 - 1, y1), (x1, y0 - 1), (x1 + 500, y0)]);
    out.extend((x0..x1).step_by(5).flat_map(|x| [(x, y0 - 1), (x, y1)]));
    out.extend((y0..y1).step_by(5).flat_map(|y| [(x0 - 1, y), (x1, y)]));
    out
}

/// The pixels `w` changes when drawn in `at`.
pub(crate) fn drawn<W: Widget>(w: W, at: Rect) -> Vec<(u32, u32)> {
    Canvas::new(at, GROUND).painted(|fb| w.paint(fb, at)).changed(GROUND)
}

/// Up to about 256 of the pixels `w` draws, spread evenly through them.
pub(crate) fn sampled<W: Widget>(w: W, at: Rect) -> impl Iterator<Item = (u32, u32)> {
    let all = drawn(w, at);
    let step = all.len().div_ceil(256).max(1);
    all.into_iter().step_by(step)
}

/// A line for the first sampled drawn pixel `hit` misses and the first point outside
/// `at` it takes, naming `what`.
pub(crate) fn disagree<W: Widget>(
    what: &str,
    w: W,
    at: Rect,
    hit: impl Fn(i32, i32) -> bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let missed = sampled(w, at).find(|&(x, y)| !hit(x as i32, y as i32));
    out.extend(missed.map(|p| format!("{what} in {at:?}: drawn {p:?} is not hit")));
    let taken = around(at).into_iter().find(|&(x, y)| hit(x, y));
    out.extend(taken.map(|p| format!("{what} in {at:?}: outside {p:?} is hit")));
    out
}
