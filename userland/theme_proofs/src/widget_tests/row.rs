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

//! Row: every option stays in the box and the hit test takes the body it
//! draws.

use nonos_toolkit::widgets::{Ink, Row};

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::samples::LONG;
use super::serial::serial;

/// One row for each option that changes the drawing, and rows that combine
/// them.
pub(crate) fn variants() -> Vec<(String, Row<'static>)> {
    let named = |n: &str, r| (n.to_string(), r);
    let full = Row::new("Wi-Fi").value("Home").note("Connected").chevron().trailing(60);
    vec![
        named("label", Row::new("Wi-Fi")),
        named("value", Row::new("Wi-Fi").value("Home")),
        named("value ink", Row::new("Wi-Fi").value("Weak").value_ink(Ink::Warn)),
        named("note", Row::new("Wi-Fi").note("Connected to Home")),
        named("chevron", Row::new("Wi-Fi").chevron()),
        named("trailing", Row::new("Wi-Fi").trailing(60)),
        named("trailing wider than the row", Row::new("Wi-Fi").trailing(5000).chevron()),
        named("everything", full),
        named("long", Row::new(LONG).value(LONG).note(LONG).chevron().trailing(40)),
    ]
}

#[test]
fn row_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn row_hit_takes_the_body_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |r, at, x, y| r.hit(at, x, y));
}
