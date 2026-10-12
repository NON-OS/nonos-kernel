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

use alloc::string::String;

use nonos_app_skeleton::EventOutcome;

use crate::browser::shell::listing::{bookmark_rows, download_rows, history_rows};
use crate::browser::shell::{store, Page, Shell};
use crate::browser::state::{Origin, State};
use crate::browser::ui::list_geom::{trail, ListGeom};

/// A History row opens its page in the tab in view.
pub(super) fn history(
    state: &mut State,
    shell: &mut Shell,
    g: &ListGeom,
    x: i32,
    y: i32,
) -> EventOutcome {
    let list = history_rows(shell);
    let hit = g.row_at(x, y, list.len()).and_then(|i| shell.visits.get(list[i]));
    match hit.map(|v| v.url.clone()) {
        Some(url) => open(state, shell, url),
        None => EventOutcome::Idle,
    }
}

/// A Bookmarks row opens its page; its trailing button removes it, and the
/// bookmarks are saved merged with what another window saved.
pub(super) fn bookmark(
    state: &mut State,
    shell: &mut Shell,
    g: &ListGeom,
    x: i32,
    y: i32,
) -> EventOutcome {
    let list = bookmark_rows(shell);
    let Some(i) = g.row_at(x, y, list.len()) else {
        return EventOutcome::Idle;
    };
    let Some(url) = shell.bookmarks.get(list[i]).map(|b| b.url.clone()) else {
        return EventOutcome::Idle;
    };
    if !trail(g.row_rect(i)).contains(x, y) {
        return open(state, shell, url);
    }
    shell.toggle_bookmark(&url, "", 0);
    store::sync(shell);
    EventOutcome::Repaint
}

/// A Downloads row's trailing button drops its record; the saved file stays.
pub(super) fn download(shell: &mut Shell, g: &ListGeom, x: i32, y: i32) -> EventOutcome {
    let list = download_rows(shell);
    match g.row_at(x, y, list.len()) {
        Some(i) if trail(g.row_rect(i)).contains(x, y) => {
            shell.downloads.remove(list[i]);
            EventOutcome::Repaint
        }
        _ => EventOutcome::Idle,
    }
}

/* Sends the tab in view to `url` and shows it. */
fn open(state: &mut State, shell: &mut Shell, url: String) -> EventOutcome {
    shell.show(Page::Web);
    super::navigate::navigate(state, url, Origin::User)
}
