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

use crate::browser::omnibox::Change;
use crate::browser::shell::visits::record;
use crate::browser::shell::Shell;
use crate::browser::state::State;

/* The page a load committed goes into the window's visit log. A start page
 * on screen counts visits in its cards, so it is drawn again. */
pub(super) fn drain(state: &mut State, shell: &mut Shell) {
    let Some(url) = state.visited.take() else { return };
    record(&mut shell.visits, &url);
    if state.on_start {
        state.mark(Change::Page);
    }
}
