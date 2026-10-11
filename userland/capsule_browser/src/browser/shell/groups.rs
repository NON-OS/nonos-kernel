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

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::kept::Group;

pub const MAX_GROUPS: usize = 8;
pub const MAX_NAME: usize = 32;
const COLORS: u8 = 8;

/// Appends `Group N` under the lowest id no group holds, coloured by its id.
/// None once the window has `MAX_GROUPS`.
pub fn create(groups: &mut Vec<Group>) -> Option<u8> {
    if groups.len() >= MAX_GROUPS {
        return None;
    }
    let id = (0..=u8::MAX).find(|i| groups.iter().all(|g| g.id != *i))?;
    let name = format!("Group {}", id as u32 + 1);
    groups.push(Group { id, name, color: id % COLORS });
    Some(id)
}

/// Gives group `id` the name `name`, trimmed and cut to `MAX_NAME` chars.
/// False, and nothing changed, for a blank name or an unknown id.
pub fn rename(groups: &mut [Group], id: u8, name: &str) -> bool {
    let name: String = name.trim().chars().take(MAX_NAME).collect();
    let name = String::from(name.trim_end());
    match groups.iter_mut().find(|g| g.id == id) {
        Some(g) if !name.is_empty() => {
            g.name = name;
            true
        }
        _ => false,
    }
}

/// Drops group `id`. The caller clears the group from the tabs that held it.
pub fn remove(groups: &mut Vec<Group>, id: u8) -> bool {
    let before = groups.len();
    groups.retain(|g| g.id != id);
    groups.len() != before
}

/// The group after `current` in list order: no group, the first, ..., the
/// last, then no group again. An id no group holds starts over at the first.
pub fn cycle(current: Option<u8>, groups: &[Group]) -> Option<u8> {
    let next = match current {
        None => 0,
        Some(id) => groups.iter().position(|g| g.id == id).map_or(0, |i| i + 1),
    };
    groups.get(next).map(|g| g.id)
}

/// The group with id `id`.
pub fn find(groups: &[Group], id: u8) -> Option<&Group> {
    groups.iter().find(|g| g.id == id)
}

/// The tabs, by index, that a page filtered to `filter` shows: all of them,
/// or those in that group. `members[i]` is tab `i`'s group.
pub fn members(filter: Option<u8>, members: &[Option<u8>]) -> Vec<usize> {
    let keep = |g: &Option<u8>| filter.is_none() || *g == filter;
    members.iter().enumerate().filter(|(_, g)| keep(g)).map(|(i, _)| i).collect()
}

/// How many of the tabs in `members` are in group `id`.
pub fn count(id: u8, members: &[Option<u8>]) -> usize {
    members.iter().filter(|g| **g == Some(id)).count()
}
