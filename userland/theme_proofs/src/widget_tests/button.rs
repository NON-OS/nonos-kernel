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

//! Button: every kind stays in its box and the hit test takes the body it
//! draws.

use nonos_toolkit::widgets::{Button, Kind};

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::samples::LONG;
use super::serial::serial;

/// The four kinds, by name.
pub(crate) const KINDS: [(&str, Kind); 4] = [
    ("primary", Kind::Primary),
    ("secondary", Kind::Secondary),
    ("plain", Kind::Plain),
    ("danger", Kind::Danger),
];

fn variants() -> Vec<(String, Button<'static>)> {
    let mut all = Vec::new();
    for (name, kind) in KINDS {
        for label in ["Save", "Grüße — 日本語", LONG] {
            all.push((format!("{name} {label:?}"), Button::new(label).kind(kind)));
        }
    }
    all
}

#[test]
fn button_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn button_hit_takes_the_body_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |b, at, x, y| b.hit(at, x, y));
}
