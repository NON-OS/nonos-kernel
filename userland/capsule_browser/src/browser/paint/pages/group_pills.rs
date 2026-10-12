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

use crate::browser::paint::pages::pills::{Pick, Pill};
use crate::browser::paint::tokens;
use crate::browser::shell::groups::MAX_GROUPS;
use crate::browser::shell::Shell;

const ALL: &str = "All";
const NEW: &str = "+ New group";

/// The Tabs page's pills: All, each group under its colour dot, then New
/// group, dimmed once the window holds `MAX_GROUPS`.
pub fn specs(shell: &Shell) -> Vec<Pill> {
    let on = shell.group_filter;
    let mut out = Vec::with_capacity(shell.groups.len() + 2);
    out.push(pill(String::from(ALL), None, on.is_none(), Pick::Group(None)));
    for g in shell.groups.iter() {
        let dot = tokens::TILES[g.color as usize % tokens::TILES.len()];
        out.push(pill(g.name.clone(), Some(dot), on == Some(g.id), Pick::Group(Some(g.id))));
    }
    let mut new = pill(String::from(NEW), None, false, Pick::NewGroup);
    new.dim = shell.groups.len() >= MAX_GROUPS;
    out.push(new);
    out
}

fn pill(label: String, dot: Option<u32>, on: bool, pick: Pick) -> Pill {
    Pill { label, count: None, on, dot, dim: false, pick }
}
