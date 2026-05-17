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

use nonos_app_skeleton::{EventOutcome, InputEvent};

use super::actions;
use super::keys::{classify, Key};
use super::state::State;

pub fn on_event(state: &mut State, event: InputEvent) -> EventOutcome {
    if !event.is_key_down() {
        return EventOutcome::Idle;
    }
    match classify(event.code) {
        Key::Close => EventOutcome::Close,
        Key::Ignored => EventOutcome::Idle,
        Key::Digit(d) => act(state, |s| actions::input_digit(s, d)),
        Key::Decimal => act(state, actions::input_decimal),
        Key::Operator(op) => act(state, |s| actions::set_operator(s, op)),
        Key::Equals => act(state, actions::equals),
        Key::Clear => act(state, actions::clear),
        Key::Negate => act(state, actions::negate),
        Key::Percent => act(state, actions::percent),
    }
}

fn act<F: FnOnce(&mut State)>(state: &mut State, f: F) -> EventOutcome {
    f(state);
    EventOutcome::Repaint
}
