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

//! Switch: on and off stay in the box, the hit test takes the track it
//! draws, and the knob reads on the track. The on knob is `on_accent` on
//! `accent`, a pair colours.md holds; the off knob's tints have no floor.

use nonos_toolkit::widgets::Switch;

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::hide::Hide;
use super::legible::{assert_legible, Off, Read, NONE};
use super::serial::serial;
use crate::wcag::LARGE;

fn variants() -> Vec<(String, Switch)> {
    vec![("on".to_string(), Switch::new(true)), ("off".to_string(), Switch::new(false))]
}

#[test]
fn switch_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn switch_hit_takes_the_track_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |s, at, x, y| s.hit(at, x, y));
}

#[test]
fn switch_knob_reads_on_its_track() {
    let _g = serial();
    let knob = || Off::Hide(Hide::Dots);
    assert_legible(&[
        Read { what: "on knob", on: Switch::new(true), off: knob(), floor: LARGE },
        Read { what: "off knob", on: Switch::new(false), off: knob(), floor: NONE },
    ]);
}
