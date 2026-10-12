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
use alloc::vec::Vec;

use super::groups;
use super::window::Shell;

/// One open tab as the Tabs page draws it: what it is called, its site,
/// its group, and whether it is the tab in view. The window takes these
/// from its tabs before each paint and each event, so the painter and the
/// click handler place the same cards.
pub struct TabCard {
    pub title: String,
    pub host: String,
    pub group: Option<u8>,
    pub active: bool,
}

/// Each open tab's group, in tab order.
pub fn members(shell: &Shell) -> Vec<Option<u8>> {
    shell.cards.iter().map(|c| c.group).collect()
}

/// The tabs, by index, the Tabs page shows under the window's group filter.
pub fn shown(shell: &Shell) -> Vec<usize> {
    groups::members(shell.group_filter, &members(shell))
}
