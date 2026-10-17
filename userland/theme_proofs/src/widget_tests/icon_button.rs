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

//! IconButton: every kind, bare and labelled, stays in its box, the hit test
//! takes the body it draws, and a bare one is a square as tall as a button.

use nonos_toolkit::design::scale::set_scale;
use nonos_toolkit::icons::IconId;
use nonos_toolkit::widgets::{Button, IconButton};

use super::agree::assert_agree;
use super::bounds::assert_bounded;
use super::boxes::boxes;
use super::button::KINDS;
use super::samples::LONG;
use super::serial::{serial, SCALES};

/// The icon the proofs draw.
pub(crate) const ICON: IconId = IconId::Install;

fn variants() -> Vec<(String, IconButton<'static>)> {
    let mut all = Vec::new();
    for (name, kind) in KINDS {
        for label in ["", "Save", "Grüße — 日本語", LONG] {
            let b = IconButton::new(ICON).kind(kind).label(label);
            all.push((format!("{name} {label:?}"), b));
        }
    }
    all
}

#[test]
fn icon_button_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn icon_button_hit_takes_the_body_it_draws() {
    let _g = serial();
    assert_agree(&variants(), boxes, |b, at, x, y| b.hit(at, x, y));
}

#[test]
fn bare_icon_button_is_a_button_tall_square() {
    let _g = serial();
    for q in SCALES {
        set_scale(q);
        let h = Button::new("Save").size().1;
        assert_eq!(IconButton::new(ICON).size(), (h, h), "at {q}/4");
        assert_eq!(IconButton::new(ICON).label("Save").size().1, h, "at {q}/4");
    }
    set_scale(SCALES[0]);
}
