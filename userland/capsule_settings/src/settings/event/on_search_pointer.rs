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

use crate::settings::state::State;
use crate::settings::ui::hover::hover_to;
use crate::settings::ui::search_field::WIDTH;
use crate::settings::ui::target::Target;

pub fn on_accessory(state: &mut State, event: InputEvent) -> EventOutcome {
    if event.kind == InputKind::PointerAbs {
        return over_field(state, event.x, event.y);
    }
    if event.kind != InputKind::ButtonDown || state.search_focused {
        return EventOutcome::Idle;
    }
    state.search_focused = true;
    state.editing = false;
    EventOutcome::Repaint
}

/// A move over the titlebar field. The content's pointer is told it left,
/// since the two are never under the pointer at once. A move reaches here
/// from off the field only while a press begun on it is held, and the field
/// draws no press, so below it is not told apart.
fn over_field(state: &mut State, x: i32, y: i32) -> EventOutcome {
    state.pointer.left();
    let over = x >= 0 && y >= 0 && x < WIDTH as i32;
    hover_to(&mut state.hover, if over { Target::Search } else { Target::None })
}
