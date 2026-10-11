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

use nonos_libc::mk_time_millis;

use crate::browser::omnibox::Change;
use crate::browser::paint::toolbar::route_of;
use crate::browser::shell::site_label;
use crate::browser::shell::types::Visit;
use crate::browser::shell::visits::{host_of, record};
use crate::browser::shell::Shell;
use crate::browser::state::State;

/* The page a load committed goes into the window's visit log, under the
 * title it committed with and the route it came by. A page the window
 * draws itself counts or lists visits, so it is drawn again. */
pub(super) fn drain(state: &mut State, shell: &mut Shell) {
    let Some(url) = state.visited.take() else { return };
    let (host, route) = (host_of(&url), route_of(state));
    let title = site_label::title(&state.title, &url);
    record(&mut shell.visits, Visit { url, title, host, at_ms: mk_time_millis(), route });
    if state.on_own {
        state.mark(Change::Page);
    }
}
