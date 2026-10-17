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

//! Feeds the pointer and names the sidebar entry under it, so an entry draws
//! hover and press and a move repaints only on crossing to another entry. The
//! entries are About's only controls; the pane is evidence to read.

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind};
use nonos_toolkit::widgets::{Pointer, State as Look};

use crate::about::section::Section;

use super::hit;

/// Moves and releases, neither of which clicks; None for any other event. The
/// input router says the pointer left with a move to (-1, -1), which lands
/// left of and above the content. A release repaints what may have been held.
pub fn on_pointer(
    p: &mut Pointer,
    hover: &mut Option<Section>,
    ev: &InputEvent,
) -> Option<EventOutcome> {
    match ev.kind {
        InputKind::PointerAbs if ev.x < 0 && ev.y < 0 => p.left(),
        InputKind::PointerAbs => p.moved(ev.x, ev.y),
        InputKind::ButtonUp => p.released(),
        _ => return None,
    }
    let held = ev.kind == InputKind::ButtonUp && hover.is_some();
    let moved = rehover(p, hover);
    Some(if held || moved { EventOutcome::Repaint } else { EventOutcome::Idle })
}

/// Names the entry under the pointer again, by the test a click makes; true
/// when that changed.
pub fn rehover(p: &Pointer, hover: &mut Option<Section>) -> bool {
    let next = p.position().and_then(|(x, y)| hit::at(x, y));
    core::mem::replace(hover, next) != next
}

/// The hover and press the entry for `s` draws. Only the entry under the
/// hover asks the pointer, so a paint walks the rail once more at most.
pub fn look(p: &Pointer, hover: Option<Section>, s: Section) -> Look {
    if hover != Some(s) {
        return Look::default();
    }
    p.state(|x, y| hit::at(x, y) == Some(s))
}
