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

/// What the content area shows. `Web` is the tab's own view: its page, or
/// the start page while it has none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Page {
    Start,
    #[default]
    Web,
}

/// A page committed this session, kept only in memory.
pub struct Visit {
    pub url: String,
    pub host: String,
}

/// A page kept for the start page's favourites.
pub struct Bookmark {
    pub url: String,
    pub title: String,
}
