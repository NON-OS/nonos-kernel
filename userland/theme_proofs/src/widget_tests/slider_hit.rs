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

//! Slider: inside its box the hit test gives a value in range, and at the
//! centre of the knob it was drawn with, that knob's value.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::widgets::{Slider, State};

use super::boxes::boxes;
use super::canvas::Canvas;
use super::serial::{serial, SCALES};

#[test]
fn slider_hit_gives_the_value_of_the_knob_drawn_there() {
    let _g = serial();
    let mut fails = Vec::new();
    for q in SCALES {
        set_scale(q);
        for at in boxes(Slider::new(0, 10).size()).into_iter().take(2) {
            for v in 0..=10 {
                let s = Slider::new(v, 10);
                let hover = State { hovered: true, ..State::default() };
                let draw = |s: Slider| Canvas::new(at, 0).painted(|fb| s.draw(fb, at));
                let knob = draw(s.state(hover)).diff(&draw(s));
                let (xs, ys): (Vec<u32>, Vec<u32>) = knob.into_iter().unzip();
                let mid = |a: &[u32]| (a.iter().min().unwrap() + a.iter().max().unwrap()) / 2;
                let (cx, cy) = (mid(&xs) as i32, mid(&ys) as i32);
                let got = s.hit(at, cx, cy);
                if got != Some(v) {
                    fails.push(format!("{v} in {at:?} at {q}/4: knob at {cx},{cy} hits {got:?}"));
                }
                let inside =
                    (at.x..at.x + at.w).flat_map(|x| (at.y..at.y + at.h).map(move |y| (x, y)));
                let wild = inside
                    .map(|(x, y)| s.hit(at, x as i32, y as i32))
                    .find(|h| h.is_some_and(|h| h > 10));
                fails.extend(wild.map(|h| format!("{v} in {at:?} at {q}/4: hit gave {h:?}")));
            }
        }
    }
    set_scale(SCALES[0]);
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
