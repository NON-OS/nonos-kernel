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

use super::types::Bookmark;

pub const MAX_BOOKMARKS: usize = 256;

/// True when `url` is bookmarked.
pub fn contains(bookmarks: &[Bookmark], url: &str) -> bool {
    bookmarks.iter().any(|b| b.url == url)
}

/// Removes the bookmark for `url` when there is one, otherwise adds it.
/// Returns whether `url` is bookmarked afterwards: an empty URL, or a full
/// list, leaves it unbookmarked.
pub fn toggle(bookmarks: &mut Vec<Bookmark>, url: &str, title: &str, at_ms: i64) -> bool {
    if let Some(i) = bookmarks.iter().position(|b| b.url == url) {
        bookmarks.remove(i);
        return false;
    }
    if url.is_empty() || bookmarks.len() >= MAX_BOOKMARKS {
        return false;
    }
    bookmarks.push(Bookmark { url: String::from(url), title: String::from(title), at_ms });
    true
}
