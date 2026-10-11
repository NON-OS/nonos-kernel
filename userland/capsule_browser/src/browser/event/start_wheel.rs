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

use crate::browser::omnibox::Change;
use crate::browser::paint::start::{favourites, geom};
use crate::browser::shell::Shell;
use crate::browser::state::State;

const WHEEL_STEP: i32 = 60;

/* The wheel over the start page moves it within its height, held where
 * the painter would hold it, unless the settings panel is over it. A notch
 * at either end changes nothing. */
pub(super) fn start_wheel(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    if state.settings_open {
        return EventOutcome::Idle;
    }
    let favs = favourites(shell).len();
    let (w, h) = (state.viewport_w as i32, state.viewport_h as i32);
    let at = -geom(shell, favs, w, h).hero.y;
    shell.page_scroll = at.saturating_sub(event.delta_y.saturating_mul(WHEEL_STEP));
    shell.page_scroll = -geom(shell, favs, w, h).hero.y;
    if shell.page_scroll == at {
        return EventOutcome::Idle;
    }
    state.mark(Change::Page);
    EventOutcome::Repaint
}
