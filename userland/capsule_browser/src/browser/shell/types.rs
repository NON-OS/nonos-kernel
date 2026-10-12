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

use super::route::Route;

/// What the content area shows. `Web` is the tab's own view: its page, or
/// the start page while it has none. The rest the window draws itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Page {
    Start,
    #[default]
    Web,
    Tabs,
    Bookmarks,
    Downloads,
    History,
    Reader,
    Settings,
}

/// A page committed this session, kept only in memory: what it was called,
/// when, and the route its traffic took.
pub struct Visit {
    pub url: String,
    pub title: String,
    pub host: String,
    pub at_ms: i64,
    pub route: Route,
}

/// A page kept for the start page's favourites. `at_ms` is when it was
/// starred, which decides between two windows' copies of it.
#[derive(Clone)]
pub struct Bookmark {
    pub url: String,
    pub title: String,
    pub at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DlState {
    Saving,
    Saved,
    Failed(String),
}

/// A download this session: `name` is the file it is saved as.
pub struct Download {
    pub name: String,
    pub url: String,
    pub bytes: u64,
    pub at_ms: i64,
    pub state: DlState,
}

/// A response the engine could not show, handed from a tab to the window.
/// `body` is `None` when it was too large to keep.
pub struct Downloaded {
    pub url: String,
    pub bytes: u64,
    pub body: Option<Vec<u8>>,
}

/// A download recorded as `Saving` whose body still waits to be written.
pub struct PendingSave {
    pub url: String,
    pub at_ms: i64,
    pub name: String,
    pub body: Vec<u8>,
}
