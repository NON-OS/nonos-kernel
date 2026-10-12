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

use crate::browser::shell::downloads::push_saved;
use crate::browser::shell::save_dl;
use crate::browser::shell::Shell;
use crate::browser::state::State;

/* One save a tick, the oldest waiting, and none while the tab in view
 * loads, so a page on screen never waits behind a save. True when one was
 * written or refused. */
pub(super) fn save_next(active: &State, shell: &mut Shell) -> bool {
    if shell.saving.is_empty() || active.loading() {
        return false;
    }
    let job = shell.saving.remove(0);
    let saved = save_dl::save(&job.name, &job.body);
    push_saved(&mut shell.downloads, &job.url, job.at_ms, saved);
    true
}
