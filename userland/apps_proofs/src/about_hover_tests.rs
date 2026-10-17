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

//! About's sidebar: the input router's leave names nothing and lights nothing,
//! and a press lights only the entry it began on.

use nonos_app_skeleton::EventOutcome::{Idle, Repaint};
use nonos_app_skeleton::InputKind::{ButtonDown, ButtonUp, PointerAbs};
use nonos_toolkit::widgets::{Pointer, State as Look};

use crate::about::section::SECTIONS;
use crate::about::ui::hover::rehover;
use crate::about_nav_tests::{points, Rail};

#[test]
fn the_leave_names_nothing_and_lights_nothing() {
    let mut rail = Rail(Pointer::new(), None);
    rail.feed(PointerAbs, points(2)[4]);
    assert!(rail.look(2).hovered);
    assert!(rail.feed(PointerAbs, (-1, -1)) == Some(Repaint));
    assert!(rail.1.is_none() && rail.0.position().is_none());
    assert!((0..SECTIONS.len()).all(|i| rail.look(i) == Look::default()));
    assert!(rail.feed(PointerAbs, (-1, -1)) == Some(Idle));
}

#[test]
fn a_press_lights_only_its_entry_and_its_release_repaints() {
    let (mut rail, at) = (Rail(Pointer::new(), None), points(1)[4]);
    rail.0.pressed(at.0, at.1);
    assert!(rehover(&rail.0, &mut rail.1));
    assert!(rail.look(1).pressed && !rail.look(0).pressed);
    assert!(rail.feed(ButtonUp, at) == Some(Repaint));
    assert!(!rail.look(1).pressed && rail.look(1).hovered);
    assert!(rail.feed(ButtonDown, at).is_none());
}
