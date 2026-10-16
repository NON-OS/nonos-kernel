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

//! Label: every role, ink and alignment stays in its box, and every ink reads
//! on every ground at its floor.

use nonos_toolkit::design::text_role::TextRole;
use nonos_toolkit::widgets::{Align, Ink, Label};

use super::bounds::assert_bounded;
use super::legible::{assert_legible, Off, Read};
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

const TEXTS: [&str; 2] = ["Network settings", "Grüße — 日本語"];

const INKS: [(&str, Ink, f64); 8] = [
    ("text", Ink::Text, BODY),
    ("text_2", Ink::Text2, BODY),
    ("muted", Ink::Muted, BODY),
    ("quiet", Ink::Quiet, LARGE),
    ("accent", Ink::Accent, BODY),
    ("ok", Ink::Ok, BODY),
    ("warn", Ink::Warn, BODY),
    ("danger", Ink::Danger, BODY),
];

#[test]
fn label_paints_inside_its_box() {
    let _g = serial();
    let mut all = Vec::new();
    for text in TEXTS {
        for role in [TextRole::Body, TextRole::Title, TextRole::Headline] {
            for align in [Align::Left, Align::Centre, Align::Right] {
                let name = format!("{text:?} {role:?} {align:?}");
                all.push((name, Label::new(text).role(role).align(align)));
            }
        }
        all.extend(
            INKS.map(|(what, ink, _)| (format!("{text:?} {what}"), Label::new(text).ink(ink))),
        );
    }
    assert_bounded(&all);
}

#[test]
fn label_inks_read_on_every_ground() {
    let _g = serial();
    let read = |(what, ink, floor): (&'static str, Ink, f64)| Read {
        what,
        on: Label::new(TEXTS[1]).ink(ink),
        off: Off::Widget(Label::new("").ink(ink)),
        floor,
    };
    assert_legible(&INKS.map(read));
}
