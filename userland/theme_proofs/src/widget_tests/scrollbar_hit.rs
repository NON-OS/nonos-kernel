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

//! Scrollbar: inside its box the hit test gives an offset in range, and at
//! the centre of the thumb it was drawn with, that thumb's offset to within
//! one pixel of travel.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Scrollbar, State};

use super::canvas::Canvas;
use super::scrollbar::place;
use super::serial::{serial, SCALES};

#[test]
fn scrollbar_hit_gives_the_offset_of_the_thumb_drawn_there() {
    let _g = serial();
    let (content, view) = (1000u32, 250u32);
    let most = content - view;
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for at in place(Scrollbar::new(0, content, view).size()).into_iter().take(2) {
            for off in (0..=most).step_by(25) {
                let bar = Scrollbar::new(off, content, view);
                let held = State { pressed: true, ..State::default() };
                let draw = |b: Scrollbar| Canvas::new(at, 0).painted(|fb| b.draw(fb, at));
                let ys: Vec<u32> =
                    draw(bar.state(held)).diff(&draw(bar)).into_iter().map(|p| p.1).collect();
                let (top, end) = (*ys.iter().min().unwrap(), *ys.iter().max().unwrap());
                let travel = at.h - (end - top + 1);
                let slack = most.div_ceil(travel.max(1)) + 1;
                let (x, y) = ((at.x + at.w - 1) as i32, ((top + end) / 2) as i32);
                let got = bar.hit(at, x, y).unwrap_or(u32::MAX);
                if got.abs_diff(off) > slack {
                    fails.push(format!("{off} in {at:?} at {q}/4: thumb {top}..={end} hits {got}"));
                }
                let all = (at.y..at.y + at.h).map(|y| bar.hit(at, x, y as i32));
                let wild = all.into_iter().find(|h| h.is_none_or(|h| h > most));
                fails.extend(wild.map(|h| format!("{off} in {at:?} at {q}/4: hit gave {h:?}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
