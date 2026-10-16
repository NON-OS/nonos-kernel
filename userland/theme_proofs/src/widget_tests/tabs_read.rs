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

//! Tabs: the selected label (`accent_text`) and the other labels (`muted`),
//! hovered or not, read on the strip in every state.

use nonos_toolkit::widgets::Tabs;

use super::hide::Hide;
use super::legible::{assert_legible, Off, Read};
use super::serial::serial;
use super::tabs::LABELS;
use crate::wcag::BODY;

#[test]
fn tab_labels_read_selected_hovered_or_plain() {
    let _g = serial();
    let hide = Off::Hide(Hide::Text(LABELS[1]));
    let plain = Tabs::new(&LABELS, 0);
    assert_legible(&[
        Read { what: "selected", on: Tabs::new(&LABELS, 1), off: hide, floor: BODY },
        Read { what: "unselected", on: plain, off: Off::Hide(Hide::Text(LABELS[1])), floor: BODY },
        Read {
            what: "hovered",
            on: plain.hovered(Some(1)),
            off: Off::Hide(Hide::Text(LABELS[1])),
            floor: BODY,
        },
    ]);
}
