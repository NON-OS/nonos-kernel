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

//! Checkbox: on and off, bare and labelled, stay in the box, and the hit
//! test takes the box and label it draws.

use nonos_toolkit::widgets::Checkbox;

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::samples::LONG;
use super::serial::serial;

/// The labels the proofs draw beside a mark: none, short, multi-byte and too
/// long for any box.
pub(crate) const LABELS: [&str; 4] = ["", "Wi-Fi", "Grüße — 日本語", LONG];

fn variants() -> Vec<(String, Checkbox<'static>)> {
    let mut all = Vec::new();
    for on in [true, false] {
        for label in LABELS {
            all.push((format!("on {on} {label:?}"), Checkbox::new(on).label(label)));
        }
    }
    all
}

#[test]
fn checkbox_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn checkbox_hit_takes_the_box_and_label_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |c, at, x, y| c.hit(at, x, y));
}
