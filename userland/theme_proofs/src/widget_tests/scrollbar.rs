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

//! Scrollbar: every offset stays in the box, short boxes included, the hit
//! test takes what it draws and nothing outside, and content that fits
//! draws and hits nothing.

use nonos_toolkit::widgets::{Rect, Scrollbar};

use super::agree::assert_agree;
use super::bounds::assert_bounded_in;
use super::boxes::boxed;
use super::hits::drawn;
use super::serial::serial;

/// A bar's boxes: tall, wide, shorter than the thumb's least length, and
/// narrower than the bar.
pub(crate) fn place((w, _): (u32, u32)) -> [Rect; 4] {
    [boxed(w, 160), boxed(w + 60, 200), boxed(w, 12), boxed(2, 160)]
}

fn variants() -> Vec<(String, Scrollbar)> {
    let cases = [(0, 1000, 250), (375, 1000, 250), (750, 1000, 250), (9999, 1000, 250)];
    let more = [(0, 100_000, 10), (5, 251, 250), (0, 250, 250), (0, 200, 250)];
    let all = cases.into_iter().chain(more);
    all.map(|(o, c, v)| (format!("{o} of {c} through {v}"), Scrollbar::new(o, c, v))).collect()
}

#[test]
fn scrollbar_paints_inside_its_box() {
    let _g = serial();
    assert_bounded_in(&variants(), place);
}

#[test]
fn scrollbar_hit_takes_what_it_draws() {
    let _g = serial();
    assert_agree(&variants(), place, |s, at, x, y| s.hit(at, x, y).is_some());
}

#[test]
fn scrollbar_that_fits_draws_and_hits_nothing() {
    let _g = serial();
    for bar in [Scrollbar::new(0, 250, 250), Scrollbar::new(3, 0, 250), Scrollbar::new(0, 0, 0)] {
        let at = place(bar.size())[1];
        assert!(drawn(bar, at).is_empty(), "{bar:?} drew");
        let all = (at.x..at.x + at.w).flat_map(|x| (at.y..at.y + at.h).map(move |y| (x, y)));
        let hit = all.into_iter().find(|&(x, y)| bar.hit(at, x as i32, y as i32).is_some());
        assert!(hit.is_none(), "{bar:?} hit at {hit:?}");
    }
}
