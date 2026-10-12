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
use crate::browser::state::State;
use crate::browser::ui::sidebar_geom::RowKind;

/// The sidebar row standing for the page in the content area; none for the
/// tab's own page.
pub fn current(state: &State, shell: &Shell) -> Option<RowKind> {
    if state.on_start {
        return Some(RowKind::Start);
    }
    match shell.page {
        Page::Tabs => Some(tabs_row(shell)),
        Page::Bookmarks => Some(RowKind::Bookmarks),
        Page::Reader => Some(RowKind::Reader),
        Page::Downloads => Some(RowKind::Downloads),
        Page::History => Some(RowKind::History),
        Page::Settings => Some(RowKind::Settings),
        Page::Start | Page::Web => None,
    }
}

/* Tabs, or the group the Tabs page is filtered to. */
fn tabs_row(shell: &Shell) -> RowKind {
    let at = |id| shell.groups.iter().position(|g| g.id == id);
    shell.group_filter.and_then(at).map_or(RowKind::Tabs, RowKind::Group)
}
