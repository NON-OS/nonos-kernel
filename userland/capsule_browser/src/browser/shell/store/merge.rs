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

use super::codec::Persisted;
use crate::browser::shell::bookmarks::MAX_BOOKMARKS;
use crate::browser::shell::types::Bookmark;

/// What a save writes when another window may have saved since this one
/// loaded: the union of `disk` and `mine`, less what this window removed.
/// A bookmark keeps its newest copy, and the oldest go past the cap.
pub fn merge(disk: Persisted, mine: Persisted, removed_bookmarks: &[String]) -> Persisted {
    Persisted { bookmarks: bookmarks(disk.bookmarks, mine.bookmarks, removed_bookmarks) }
}

fn bookmarks(disk: Vec<Bookmark>, mine: Vec<Bookmark>, removed: &[String]) -> Vec<Bookmark> {
    let mut out: Vec<Bookmark> = Vec::new();
    for b in mine.into_iter().chain(disk) {
        if removed.contains(&b.url) {
            continue;
        }
        match out.iter_mut().find(|o| o.url == b.url) {
            Some(o) if b.at_ms > o.at_ms => *o = b,
            Some(_) => {}
            None => out.push(b),
        }
    }
    out.sort_by_key(|b| b.at_ms);
    let over = out.len().saturating_sub(MAX_BOOKMARKS);
    out.drain(..over);
    out
}
