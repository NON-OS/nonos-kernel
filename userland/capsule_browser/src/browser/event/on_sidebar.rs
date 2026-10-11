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
use crate::browser::shell::{Page, Shell};
use crate::browser::state::State;
use crate::browser::ui::sidebar_geom::{self, RowKind};

/* A click in the sidebar, in window coordinates, hit-tested against the
 * rows the last paint drew. Start Page shows the start page over the tab;
 * Settings opens or closes the settings panel. */
pub(super) fn on_sidebar(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    let lay = state.layout;
    match sidebar_geom::hit(lay.rail, lay.sidebar, event.x, event.y) {
        Some(RowKind::Start) => shell.show(Page::Start),
        Some(RowKind::Settings) => state.settings_open = !state.settings_open,
        None => return EventOutcome::Idle,
    }
    state.mark(Change::Full);
    EventOutcome::Repaint
}
