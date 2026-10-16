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

//! Field: the text reads at 4.5:1 and the placeholder and icon, both
//! `quiet`, at 3:1, on the field's body in every state.

use nonos_toolkit::icons::IconId;
use nonos_toolkit::widgets::Field;

use super::legible::{assert_legible, Off, Read};
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

#[test]
fn field_text_placeholder_and_icon_read_in_every_state() {
    let _g = serial();
    let blank = Field::new("");
    assert_legible(&[
        Read {
            what: "text",
            on: Field::new("Grüße — 日本語"),
            off: Off::Widget(blank),
            floor: BODY,
        },
        Read {
            what: "placeholder",
            on: blank.placeholder("Grüße — 日本語"),
            off: Off::Widget(blank),
            floor: LARGE,
        },
        Read {
            what: "icon",
            on: blank.icon(IconId::SettingsSearch),
            off: Off::Widget(blank),
            floor: LARGE,
        },
    ]);
}
