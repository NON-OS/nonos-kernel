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

use super::bookmarks;
use super::store::Persisted;
use super::window::Shell;

impl Shell {
    /// What of this window is kept across runs.
    pub fn persisted(&self) -> Persisted {
        Persisted {
            bookmarks: self.bookmarks.clone(),
            groups: self.groups.clone(),
            reader: self.reader,
            appearance: self.appearance,
            search: self.search.clone(),
        }
    }

    /// Adds or removes the bookmark for `url`, noting a removal so a merge
    /// with another window's save does not bring it back.
    pub fn toggle_bookmark(&mut self, url: &str, title: &str, at_ms: i64) {
        let had = bookmarks::contains(&self.bookmarks, url);
        bookmarks::toggle(&mut self.bookmarks, url, title, at_ms);
        self.removed_bookmarks.retain(|u| u != url);
        if had {
            self.removed_bookmarks.push(String::from(url));
        }
    }

    /// Removes every bookmark, noting each removal so a merge with another
    /// window's save does not bring it back.
    pub fn remove_all_bookmarks(&mut self) {
        for b in core::mem::take(&mut self.bookmarks) {
            self.removed_bookmarks.retain(|u| *u != b.url);
            self.removed_bookmarks.push(b.url);
        }
    }

    /// Takes on what an earlier run, or another window, kept: a group id
    /// seen twice keeps its first entry, and the reader settings are held to
    /// the choices the reader offers.
    pub fn apply(&mut self, p: Persisted) {
        self.bookmarks = p.bookmarks;
        self.groups = Vec::new();
        for g in p.groups {
            if self.groups.iter().all(|h| h.id != g.id) {
                self.groups.push(g);
            }
        }
        self.reader = p.reader.clamped();
        self.appearance = p.appearance;
        self.search = p.search;
    }
}
