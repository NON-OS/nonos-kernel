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

//! Card: the title and the note read on the card in every state.

use nonos_toolkit::widgets::Card;

use super::legible::{assert_legible, Off, Read};
use super::samples::LONG;
use super::serial::serial;
use crate::wcag::BODY;

#[test]
fn card_title_and_note_read_in_every_state() {
    let _g = serial();
    let note = |n| Card::new().title("Network").note(n);
    assert_legible(&[
        Read {
            what: "title",
            on: Card::new().title(LONG),
            off: Off::Widget(Card::new().title("")),
            floor: BODY,
        },
        Read { what: "note", on: note(LONG), off: Off::Widget(note("")), floor: BODY },
    ]);
}
