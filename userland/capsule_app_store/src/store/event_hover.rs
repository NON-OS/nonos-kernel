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

//! Feeds the pointer and names what is under it after each step, so widgets
//! draw hover and press and a move repaints only on crossing to a new target.

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind};

use super::state::State;
use super::ui::hover::{hover_to, target_at};
use super::ui::target::Target;

/// Moves and releases, neither of which clicks; None for every other event,
/// which `on_event` handles as before. A touch reaches the app as a button
/// press, since the skeleton turns one into the other before it arrives. The
/// input router says the pointer left the window with a move to (-1, -1) in
/// window coordinates, which lands left of and above the content. A release
/// repaints whatever was under the pointer, since that may have been drawn
/// pressed.
pub(super) fn on_hover(state: &mut State, event: &InputEvent) -> Option<EventOutcome> {
    let p = &mut state.pointer;
    match event.kind {
        InputKind::PointerAbs if event.x < 0 && event.y < 0 => p.left(),
        InputKind::PointerAbs => p.moved(event.x, event.y),
        InputKind::ButtonUp => p.released(),
        _ => return None,
    }
    let held = event.kind == InputKind::ButtonUp && state.hover != Target::None;
    let out = rehover(state);
    Some(if held { EventOutcome::Repaint } else { out })
}

/// A press clicks at once, on button-down, as it always has. The pointer is
/// told first, so the repaint the click asks for already draws the press;
/// a press on a target that changes nothing still repaints to draw it.
pub(super) fn press(state: &mut State, x: i32, y: i32) -> EventOutcome {
    state.pointer.pressed(x, y);
    let out = super::event_click::on_click(state, x, y);
    let moved = rehover(state);
    match moved == EventOutcome::Repaint || state.hover != Target::None {
        true => EventOutcome::Repaint,
        false => out,
    }
}

/// Names the target under the pointer again, after it moved or what is on
/// screen changed under it, and asks for a repaint only when it changed.
pub(super) fn rehover(state: &mut State) -> EventOutcome {
    let at = state.pointer.position();
    let next = at.map_or(Target::None, |(x, y)| target_at(state, x, y));
    hover_to(&mut state.hover, next)
}
