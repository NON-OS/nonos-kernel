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

//! Slider: every value stays in the box, the hit test takes what it draws
//! and nothing outside, and knob and fill are drawn visibly. colours.md
//! holds neither the knob over the fill's end nor the fill on the track to
//! a floor.

use nonos_toolkit::widgets::Slider;

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::hide::Hide;
use super::legible::{assert_legible, Off, Read, NONE};
use super::serial::serial;

/// Values from empty to full, past the maximum, and with no range at all.
pub(crate) fn variants() -> Vec<(String, Slider)> {
    let cases = [(0, 10), (5, 10), (10, 10), (15, 10), (0, 0), (3, 7), (999, 1000)];
    cases.map(|(v, m)| (format!("{v} of {m}"), Slider::new(v, m))).to_vec()
}

#[test]
fn slider_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn slider_hit_takes_what_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |s, at, x, y| s.hit(at, x, y).is_some());
}

#[test]
fn slider_knob_and_fill_are_drawn_visibly() {
    let _g = serial();
    let half = Slider::new(5, 10);
    assert_legible(&[
        Read { what: "knob", on: half, off: Off::Hide(Hide::Dots), floor: NONE },
        Read { what: "fill", on: half, off: Off::Hide(Hide::Round(1)), floor: NONE },
    ]);
}
