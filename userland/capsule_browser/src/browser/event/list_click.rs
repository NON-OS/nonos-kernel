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

use crate::browser::paint::pages::extent::page_scroll;
use crate::browser::paint::pages::pills::{self, Pick};
use crate::browser::shell::{Page, Shell};
use crate::browser::tab_groups;
use crate::browser::tabs::Tabs;
use crate::browser::ui::list_geom::ListGeom;

use super::{list_rows, tab_click};

/// A click at content-local `(x, y)` on a list page, hit-tested against the
/// geometry the page was painted with: a pill sets the filter or adds a
/// group, and a row or card acts for its page.
pub(super) fn click(tabs: &mut Tabs, shell: &mut Shell, x: i32, y: i32) -> EventOutcome {
    let c = tabs.active().layout.content;
    let g = ListGeom::new(c.w, c.h, page_scroll(shell, c.w, c.h));
    let (specs, widths) = pills::row(shell, &g);
    if let Some(p) = g.pill_at(&widths, x, y).and_then(|i| specs.get(i)) {
        return pick(shell, p.pick);
    }
    match shell.page {
        Page::Tabs => tab_click::click(tabs, shell, &g, x, y),
        Page::History => list_rows::history(tabs.active_mut(), shell, &g, x, y),
        Page::Bookmarks => list_rows::bookmark(tabs.active_mut(), shell, &g, x, y),
        Page::Downloads => list_rows::download(shell, &g, x, y),
        _ => EventOutcome::Idle,
    }
}

/* A pill: History's or Downloads' filter, the Tabs page's group filter, or
 * a new group. The list starts again from its top. */
fn pick(shell: &mut Shell, pick: Pick) -> EventOutcome {
    tab_groups::commit_rename(shell);
    match pick {
        Pick::Filter(i) if shell.page == Page::Downloads => shell.dl_filter = i,
        Pick::Filter(i) => shell.hist_filter = i,
        Pick::Group(id) => tab_groups::show(shell, id),
        Pick::NewGroup => {
            tab_groups::create(shell);
        }
    }
    shell.page_scroll = 0;
    EventOutcome::Repaint
}
