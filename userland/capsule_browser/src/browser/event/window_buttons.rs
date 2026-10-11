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

use nonos_app_skeleton::EventOutcome;

use crate::browser::omnibox::Change;
use crate::browser::shell::{bookmarks, site_label, Page, Shell};
use crate::browser::state::{State, View};
use crate::browser::ui::layout::SidebarMode;

/* The star files the page shown under its title, or its site when it has
 * none, and a second press takes it out again. With no page shown there
 * is nothing to file. */
pub(super) fn toggle_star(state: &mut State, shell: &mut Shell) -> EventOutcome {
    if state.view != View::Page {
        return EventOutcome::Idle;
    }
    let url = &state.ui.current_url;
    let title = site_label::title(&state.title, url);
    bookmarks::toggle(&mut shell.bookmarks, url, &title);
    state.mark(Change::Full);
    EventOutcome::Repaint
}

/* The sidebar button steps Full, Rail, Hidden. Auto showing the rail on a
 * narrow window folds straight away, as the reader asked for less. */
pub(super) fn cycle_sidebar(state: &mut State, shell: &mut Shell) -> EventOutcome {
    let folded = shell.sidebar == SidebarMode::Auto && state.layout.rail;
    shell.sidebar = if folded { SidebarMode::Hidden } else { shell.sidebar.cycled() };
    state.mark(Change::Full);
    EventOutcome::Repaint
}

/* Back from the start page shown over a loaded tab returns to that page,
 * as Back from the home page returns to the page that was left. */
pub(super) fn leave_start(state: &mut State, shell: &mut Shell) -> EventOutcome {
    shell.show(Page::Web);
    state.mark(Change::Full);
    EventOutcome::Repaint
}
