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

use nonos_app_skeleton::{EventOutcome, InputEvent, KEY_BACKSPACE, KEY_ENTER, KEY_ESC};

use super::state::State;

pub fn on_event(state: &mut State, event: InputEvent) -> EventOutcome {
    if !event.is_key_down() {
        return EventOutcome::Idle;
    }
    let changed = match event.code {
        KEY_ESC => return EventOutcome::Close,
        KEY_BACKSPACE => state.backspace(),
        KEY_ENTER => state.insert(b'\n'),
        code if code >= 0x20 && code <= 0x7E => state.insert(code as u8),
        _ => false,
    };
    if changed {
        EventOutcome::Repaint
    } else {
        EventOutcome::Idle
    }
}
