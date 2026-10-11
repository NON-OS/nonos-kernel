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

use crate::browser::paint::pages::{group_head, tab_chip};
use crate::browser::shell::cards::shown;
use crate::browser::shell::{Page, Shell};
use crate::browser::tab_groups;
use crate::browser::tabs::Tabs;
use crate::browser::ui::grid_geom::close_rect;
use crate::browser::ui::list_geom::ListGeom;

/// A click at content-local `(x, y)` on the Tabs page. Filtered to a group,
/// its name starts a rename and Delete group drops it; a click anywhere
/// else ends a rename in progress. On a card, the close button closes the
/// tab, the chip moves it to the next group, and the rest switches to it.
pub(super) fn click(
    tabs: &mut Tabs,
    shell: &mut Shell,
    g: &ListGeom,
    x: i32,
    y: i32,
) -> EventOutcome {
    let renaming = shell.rename.is_some();
    if let Some(gr) = group_head::filtered(shell) {
        let (id, name) = (gr.id, gr.name.clone());
        if group_head::name_rect(g, shell, gr).contains(x, y) {
            shell.rename.get_or_insert(name);
            return EventOutcome::Repaint;
        }
        tab_groups::commit_rename(shell);
        if group_head::delete_rect(g).contains(x, y) {
            tab_groups::delete(tabs, shell, id);
            return EventOutcome::Repaint;
        }
    }
    let shown = shown(shell);
    let cols = g.cols();
    let Some(j) = g.grid_at(x, y, shown.len(), cols) else {
        return if renaming { EventOutcome::Repaint } else { EventOutcome::Idle };
    };
    let (i, card) = (shown[j], g.grid_rect(j, cols));
    let group = shell.cards.get(i).and_then(|c| c.group);
    if close_rect(card).contains(x, y) {
        tabs.close(i);
        return EventOutcome::Repaint;
    }
    if tab_chip::rect(card, shell, group).contains(x, y) {
        tab_groups::cycle(tabs, shell, i);
        return EventOutcome::Repaint;
    }
    tabs.switch(i);
    shell.show(Page::Web);
    EventOutcome::Repaint
}
