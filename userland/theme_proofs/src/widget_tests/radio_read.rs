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

//! Radio: the dot reads on the accent fill as a non-text mark at 3:1, and
//! the label reads on the ground at 4.5:1 beside a selected or unselected
//! ring, in every live state. Disabled need only be drawn visibly.

use nonos_toolkit::widgets::Radio;

use super::hide::Hide;
use super::legible::{assert_legible, Off, Read};
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

const LABEL: &str = "Grüße — 日本語";

#[test]
fn radio_dot_and_label_read_in_every_state() {
    let _g = serial();
    let text = || Off::Hide(Hide::Text(LABEL));
    let (on, off) = (Radio::new(true).label(LABEL), Radio::new(false).label(LABEL));
    assert_legible(&[
        Read { what: "dot", on: Radio::new(true), off: Off::Hide(Hide::Dots), floor: LARGE },
        Read { what: "dot by label", on, off: Off::Hide(Hide::Dots), floor: LARGE },
        Read { what: "label by selected ring", on, off: text(), floor: BODY },
        Read { what: "label by unselected ring", on: off, off: text(), floor: BODY },
    ]);
}
