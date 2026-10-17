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
//! Feeds the pointer and names what is under it, so a control draws hover and
//! press and a move repaints only on crossing to another control.

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind};
use nonos_toolkit::widgets::State as Look;

use crate::clock::controls::{target_at, Target};
use crate::clock::state::State;

/// Moves and releases, neither of which clicks; None for any other event. The
/// input router says the pointer left with a move to (-1, -1), which lands
/// left of and above the content. A release repaints what may have been held.
pub fn on_pointer(state: &mut State, ev: &InputEvent) -> Option<EventOutcome> {
    let p = &mut state.pointer;
    match ev.kind {
        InputKind::PointerAbs if ev.x < 0 && ev.y < 0 => p.left(),
        InputKind::PointerAbs => p.moved(ev.x, ev.y),
        InputKind::ButtonUp => p.released(),
        _ => return None,
    }
    let held = ev.kind == InputKind::ButtonUp && state.hover.is_some();
    let moved = rehover(state);
    Some(if held || moved { EventOutcome::Repaint } else { EventOutcome::Idle })
}

/// Names the control under the pointer again; true when that changed.
pub fn rehover(state: &mut State) -> bool {
    let (tab, w) = (state.tab, state.win_w);
    let next = state.pointer.position().and_then(|(x, y)| target_at(tab, w, x, y));
    core::mem::replace(&mut state.hover, next) != next
}

/// The hover and press the control `t` draws. Only the control under the
/// hover asks the pointer, so a paint looks at most one control again.
pub fn look(state: &State, t: Target) -> Look {
    if state.hover != Some(t) {
        return Look::default();
    }
    let (tab, w) = (state.tab, state.win_w);
    state.pointer.state(|x, y| target_at(tab, w, x, y) == Some(t))
}
