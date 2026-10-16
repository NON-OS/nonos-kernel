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

//! SectionHeader: the title and any note stay in the box and read on every
//! ground.

use nonos_toolkit::widgets::SectionHeader;

use super::bounds::assert_bounded;
use super::legible::{assert_legible, Off, Read};
use super::samples::LONG;
use super::serial::serial;
use crate::wcag::BODY;

fn variants() -> Vec<(String, SectionHeader<'static>)> {
    let named = |n: &str, h| (n.to_string(), h);
    vec![
        named("title", SectionHeader::new("Appearance")),
        named("title and note", SectionHeader::new("Appearance").note("Colours and text size")),
        named("long note", SectionHeader::new("Grüße").note(LONG)),
        named("long", SectionHeader::new(LONG).note(LONG)),
    ]
}

#[test]
fn section_header_paints_inside_its_box() {
    let _g = serial();
    assert_bounded(&variants());
}

#[test]
fn section_header_title_and_note_read_on_every_ground() {
    let _g = serial();
    let note = |n| SectionHeader::new("Appearance").note(n);
    assert_legible(&[
        Read {
            what: "title",
            on: SectionHeader::new(LONG),
            off: Off::Widget(SectionHeader::new("")),
            floor: BODY,
        },
        Read { what: "note", on: note(LONG), off: Off::Widget(note("")), floor: BODY },
    ]);
}
