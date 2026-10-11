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
use crate::browser::tab_groups;
use crate::browser::ui::sidebar_geom::{self, RowKind};

/* A click in the sidebar, in window coordinates, hit-tested against the
 * rows the last paint drew. A page row shows its page; Tabs and the Tab
 * Groups rows show the Tabs page, filtered to a group or not; New group
 * adds one; Reading View opens or leaves the reader; Settings opens or
 * closes the settings panel. */
pub(super) fn on_sidebar(state: &mut State, shell: &mut Shell, event: InputEvent) -> EventOutcome {
    let lay = state.layout;
    let n = shell.groups.len();
    let Some(kind) = sidebar_geom::hit(lay.rail, lay.sidebar, n, event.x, event.y) else {
        return EventOutcome::Idle;
    };
    tab_groups::commit_rename(shell);
    let out = match kind {
        RowKind::Settings => {
            state.settings_open = !state.settings_open;
            EventOutcome::Repaint
        }
        RowKind::Reader => super::reader_toggle::toggle(state, shell),
        RowKind::Tabs | RowKind::AllTabs => filter(shell, None),
        RowKind::Group(i) => filter(shell, shell.groups.get(i).map(|g| g.id)),
        RowKind::NewGroup => match tab_groups::create(shell) {
            Some(_) => EventOutcome::Repaint,
            None => EventOutcome::Idle,
        },
        RowKind::Start => show(shell, Page::Start),
        RowKind::Bookmarks => show(shell, Page::Bookmarks),
        RowKind::Downloads => show(shell, Page::Downloads),
        RowKind::History => show(shell, Page::History),
    };
    if out == EventOutcome::Repaint {
        state.mark(Change::Full);
    }
    out
}

fn filter(shell: &mut Shell, id: Option<u8>) -> EventOutcome {
    tab_groups::show(shell, id);
    EventOutcome::Repaint
}

fn show(shell: &mut Shell, page: Page) -> EventOutcome {
    shell.show(page);
    EventOutcome::Repaint
}
