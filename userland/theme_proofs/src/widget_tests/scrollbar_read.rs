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

//! Scrollbar: a live thumb stands out from its track at the 3:1 non-text
//! floor in every scheme and state. A disabled bar draws nothing, so it has no
//! thumb to read.

use nonos_toolkit::widgets::Scrollbar;

use super::hide::Hide;
use super::legible::{assert_legible_in, Off, Read};
use super::serial::serial;
use super::states::looks;
use crate::wcag::LARGE;

#[test]
fn scrollbar_thumb_stands_out_from_its_track() {
    let _g = serial();
    let bar = Scrollbar::new(375, 1000, 250);
    let read = Read { what: "thumb", on: bar, off: Off::Hide(Hide::Round(1)), floor: LARGE };
    assert_legible_in(&[read], || looks().filter(|s| !s.disabled));
}
