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

use crate::browser::shell::{Page, Shell};
use crate::browser::state::{Origin, State};

/* One tick of the tab in view: start a navigation the reader asked for,
 * then step the page. A navigation the reader started brings the tab's
 * view back over the start page. The runner repaints only when something
 * visible changed since the last paint, so a page at rest costs no pixels
 * at all. */
pub(super) fn tick_body(state: &mut State, shell: &mut Shell) -> bool {
    if state.pending_nav.is_some() && state.ui.origin != Origin::Auto {
        shell.show(Page::Web);
    }
    step(state, shell);
    state.track.paint_gen != state.track.painted_gen
}

/* One step of a page, in view or not: let the network move, run the
 * page's timers, log what committed, then note what of all that shows. */
pub(super) fn step(state: &mut State, shell: &mut Shell) {
    super::nav::start_pending(state);
    super::pumps::fetch_tick(state);
    crate::browser::event::js_tick(state);
    crate::browser::event::script_stop(state);
    super::visits::drain(state, shell);
    super::print::note_changes(state);
}
