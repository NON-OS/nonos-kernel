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

//! Tab groups across the window's tabs: the shell keeps the groups, each
//! tab keeps the one it is in.

use crate::browser::shell::{groups, store, Page, Shell};
use crate::browser::tabs::Tabs;

/// The group a tab opened now joins: the Tabs page's filter while that
/// page shows, else none.
pub fn inherit(shell: &Shell) -> Option<u8> {
    shell.group_filter.filter(|_| shell.page == Page::Tabs)
}

/// Shows the Tabs page filtered to group `id`, or every tab for None.
pub fn show(shell: &mut Shell, id: Option<u8>) {
    shell.group_filter = id;
    shell.show(Page::Tabs);
}

/// Adds a group, saves the window's groups and shows the Tabs page
/// filtered to the new one. None once the window holds the most it can.
pub fn create(shell: &mut Shell) -> Option<u8> {
    let id = groups::create(&mut shell.groups)?;
    shell.removed_groups.retain(|g| *g != id);
    store::sync(shell);
    show(shell, Some(id));
    Some(id)
}

/// Moves tab `i` on to the next group in the window's list.
pub fn cycle(tabs: &mut Tabs, shell: &Shell, i: usize) {
    if let Some(s) = tabs.list.get_mut(i) {
        s.group = groups::cycle(s.group, &shell.groups);
    }
}

/// Drops group `id`, takes it off every tab that held it and shows every tab.
pub fn delete(tabs: &mut Tabs, shell: &mut Shell, id: u8) {
    if !groups::remove(&mut shell.groups, id) {
        return;
    }
    shell.removed_groups.push(id);
    for s in tabs.list.iter_mut().filter(|s| s.group == Some(id)) {
        s.group = None;
    }
    show(shell, None);
    store::sync(shell);
}

/// Ends the rename in progress, giving the filtered group the typed name
/// when it is a valid one.
pub fn commit_rename(shell: &mut Shell) {
    let (Some(name), Some(id)) = (shell.rename.take(), shell.group_filter) else {
        return;
    };
    if groups::rename(&mut shell.groups, id, &name) {
        store::sync(shell);
    }
}
