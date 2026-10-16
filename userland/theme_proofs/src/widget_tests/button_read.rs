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

//! Button: each kind's label reads on its body, or on the ground under a
//! plain button, in every state. Every label is body text, the plain one in
//! `accent_text` included, so each is held to 4.5:1.

use nonos_toolkit::widgets::{Button, Kind};

use super::button::KINDS;
use super::legible::{assert_legible, Off, Read};
use super::serial::serial;
use crate::wcag::BODY;

#[test]
fn button_labels_read_in_every_kind_and_state() {
    let _g = serial();
    let read = |(what, kind): (&'static str, Kind)| Read {
        what,
        on: Button::new("Grüße — 日本語").kind(kind),
        off: Off::Widget(Button::new("").kind(kind)),
        floor: BODY,
    };
    assert_legible(&KINDS.map(read));
}
