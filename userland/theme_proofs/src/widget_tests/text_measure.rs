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

//! `width` measures what the painter draws, and `centre_top` centres one
//! line box in a box, or starts it at the box's top when it does not fit.

use nonos_toolkit::font::ttf::line_height;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{centre_top, left, width};

use super::boxes::boxed;
use super::canvas::Canvas;
use super::samples::{sizes, RUNS};
use super::serial::serial;

#[test]
fn width_is_the_pen_advance_the_painter_returns() {
    let _g = serial();
    let at = boxed(900, 80);
    for px in sizes() {
        for s in RUNS.into_iter().chain([""]) {
            let mut pen = 0;
            let ink = roles().text;
            let _ = Canvas::new(at, 0).painted(|fb| pen = left(fb, at.x, 30, s, ink, px));
            assert_eq!(i64::from(width(s, px)), i64::from(pen) - i64::from(at.x), "{s:?} at {px}");
        }
    }
}

#[test]
fn centre_top_centres_the_line_box() {
    let _g = serial();
    for px in sizes() {
        let lh = line_height(px).max(1) as u32;
        for (y, h) in [(0, 0), (10, lh), (10, lh + 1), (7, lh + 20), (3, 200), (5, lh / 2)] {
            let top = centre_top(y, h, px);
            if h < lh {
                assert_eq!(top, y as i32, "box {y}+{h} at {px}");
                continue;
            }
            let above = top - y as i32;
            let below = (y + h) as i32 - (top + lh as i32);
            assert!(above >= 0 && below >= 0, "box {y}+{h} at {px}: {above} above, {below} below");
            assert!(below - above <= 1 && below >= above, "box {y}+{h} at {px}: off centre");
        }
    }
}
