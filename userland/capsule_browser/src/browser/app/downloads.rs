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
use crate::browser::shell::dl_name::name_of;
use crate::browser::shell::downloads::{push, push_failed};
use crate::browser::shell::types::{DlState, PendingSave};
use crate::browser::shell::Shell;
use crate::browser::state::State;
use crate::browser::tabs::Tabs;

const MAX_PENDING: usize = 4;
const BACKLOG: &str = "too many downloads waiting";

/* What any tab's loads left to download is recorded, in view or not, and
 * the oldest waiting body is written while the tab in view is not loading,
 * so a page on screen never waits behind a save. A start page on screen
 * counts downloads, as the Downloads page lists them, so it is drawn again;
 * true when it was. */
pub(super) fn tick(tabs: &mut Tabs, shell: &mut Shell) -> bool {
    let mut changed = false;
    for s in tabs.list.iter_mut() {
        changed |= take(s, shell);
    }
    changed |= super::dl_save::save_next(tabs.active(), shell);
    let active = tabs.active_mut();
    let redraw = changed && active.on_own;
    if redraw {
        active.mark(Change::Page);
    }
    redraw
}

/* A tab's download is listed as saving with its body queued, unless the
 * queue is full or the body was too large to keep. */
fn take(state: &mut State, shell: &mut Shell) -> bool {
    let Some(d) = state.downloaded.take() else { return false };
    let at_ms = mk_time_millis();
    match d.body {
        Some(_) if shell.saving.len() >= MAX_PENDING => {
            push_failed(&mut shell.downloads, &d.url, d.bytes, at_ms, BACKLOG)
        }
        Some(body) => {
            push(&mut shell.downloads, &d.url, d.bytes, at_ms, DlState::Saving);
            let name = name_of(&d.url);
            shell.saving.push(PendingSave { url: d.url, at_ms, name, body });
        }
        None => push_failed(&mut shell.downloads, &d.url, d.bytes, at_ms, "too large"),
    }
    true
}
