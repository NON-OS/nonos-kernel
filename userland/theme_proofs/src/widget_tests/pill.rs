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

//! Pill: every tone, with and without a dot, stays in the box and the hit
//! test takes the body it draws.

use nonos_toolkit::widgets::{Pill, Tone};

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::samples::LONG;
use super::serial::serial;

/// The five tones, by name.
pub(crate) const TONES: [(&str, Tone); 5] = [
    ("plain", Tone::Plain),
    ("accent", Tone::Accent),
    ("ok", Tone::Ok),
    ("warn", Tone::Warn),
    ("danger", Tone::Danger),
];

fn variants() -> Vec<(String, Pill<'static>)> {
    let mut all = Vec::new();
    for (name, tone) in TONES {
        for label in ["Online", "Grüße — 日本語", LONG] {
            let pill = Pill::new(label).tone(tone);
            all.push((format!("{name} {label:?}"), pill));
            all.push((format!("{name} {label:?} with dot"), pill.dot()));
        }
    }
    all
}

#[test]
fn pill_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn pill_hit_takes_the_body_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |p, at, x, y| p.hit(at, x, y));
}
