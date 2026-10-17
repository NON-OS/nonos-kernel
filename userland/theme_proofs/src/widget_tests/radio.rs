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

//! Radio: selected and not, bare and labelled, stay in the box, and the hit
//! test takes the ring and label it draws.

use nonos_toolkit::widgets::Radio;

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::checkbox::LABELS;
use super::serial::serial;

fn variants() -> Vec<(String, Radio<'static>)> {
    let mut all = Vec::new();
    for selected in [true, false] {
        for label in LABELS {
            all.push((format!("selected {selected} {label:?}"), Radio::new(selected).label(label)));
        }
    }
    all
}

#[test]
fn radio_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn radio_hit_takes_the_ring_and_label_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |r, at, x, y| r.hit(at, x, y));
}
