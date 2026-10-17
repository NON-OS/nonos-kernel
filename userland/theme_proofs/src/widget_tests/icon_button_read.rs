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

//! IconButton: in every kind and live state, the icon reads on the body, or
//! on the ground under a plain button, as a non-text mark at 3:1, and the
//! label beside it as body text at 4.5:1. Disabled need only be drawn
//! visibly.

use nonos_toolkit::widgets::{IconButton, Kind};

use super::button::KINDS;
use super::hide::Hide;
use super::icon_button::ICON;
use super::legible::{assert_legible, Off, Read};
use super::serial::serial;
use crate::wcag::{BODY, LARGE};

const LABEL: &str = "Grüße — 日本語";

fn reads((name, kind): (&str, Kind)) -> [Read<IconButton<'static>>; 3] {
    let (bare, labelled) = (IconButton::new(ICON).kind(kind), IconButton::new(ICON).kind(kind));
    let labelled = labelled.label(LABEL);
    let what = |part: &str| -> &'static str { format!("{name} {part}").leak() };
    let icons = || Off::Hide(Hide::Icons);
    [
        Read { what: what("icon"), on: bare, off: icons(), floor: LARGE },
        Read { what: what("icon by label"), on: labelled, off: icons(), floor: LARGE },
        Read { what: what("label"), on: labelled, off: Off::Hide(Hide::Text(LABEL)), floor: BODY },
    ]
}

#[test]
fn icon_button_icon_and_label_read_in_every_kind_and_state() {
    let _g = serial();
    let all: Vec<_> = KINDS.into_iter().flat_map(reads).collect();
    assert_legible(&all);
}
