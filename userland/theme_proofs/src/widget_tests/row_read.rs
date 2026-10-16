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

//! Row: the label, note, value in each ink and chevron read on every ground
//! in every state.

use nonos_toolkit::widgets::{Ink, Row};

use super::legible::{assert_legible, Off, Read};
use super::samples::LONG;
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

const INKS: [(&str, Ink, f64); 8] = [
    ("value text", Ink::Text, BODY),
    ("value text_2", Ink::Text2, BODY),
    ("value muted", Ink::Muted, BODY),
    ("value quiet", Ink::Quiet, LARGE),
    ("value accent", Ink::Accent, BODY),
    ("value ok", Ink::Ok, BODY),
    ("value warn", Ink::Warn, BODY),
    ("value danger", Ink::Danger, BODY),
];

#[test]
fn row_inks_read_on_every_ground_in_every_state() {
    let _g = serial();
    let base = Row::new("Wi-Fi");
    let value = |(what, ink, floor): (&'static str, Ink, f64)| Read {
        what,
        on: base.value("Grüße 日本").value_ink(ink),
        off: Off::Widget(base),
        floor,
    };
    let mut reads = vec![
        Read { what: "label", on: Row::new(LONG), off: Off::Widget(Row::new("")), floor: BODY },
        Read { what: "note", on: base.note(LONG), off: Off::Widget(base.note("")), floor: BODY },
        Read { what: "chevron", on: base.chevron(), off: Off::Widget(base), floor: LARGE },
    ];
    reads.extend(INKS.map(value));
    assert_legible(&reads);
}
