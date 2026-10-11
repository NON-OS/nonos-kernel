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

use nonos_app_skeleton::{EventOutcome, InputEvent, InputKind};

use crate::browser::omnibox::Change;
use crate::browser::shell::Shell;
use crate::browser::state::State;

/* Route one input event. Handlers record what they changed; one that asks
 * for a repaint without saying what changed gets the whole window, and one
 * that recorded a change gets its repaint even when it answered Idle. */
pub fn on_event(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    let before = state.track.paint_gen;
    let out = match event.kind {
        InputKind::ButtonDown => super::on_button::on_button(state, shell, event),
        InputKind::Wheel => super::scroll_by::on_wheel(state, event),
        InputKind::KeyDown => super::on_keydown::on_keydown(state, event),
        InputKind::KeyUp => super::page_input::on_keyup(state, event),
        InputKind::PointerAbs => super::on_pointer::on_pointer(state, event),
        _ => EventOutcome::Idle,
    };
    let marked = state.track.paint_gen != before;
    match out {
        EventOutcome::Repaint if !marked => {
            state.mark(Change::Full);
            out
        }
        EventOutcome::Idle if marked => EventOutcome::Repaint,
        _ => out,
    }
}
