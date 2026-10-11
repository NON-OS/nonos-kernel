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

use alloc::vec::Vec;

use super::types::Page;
use super::window::Shell;
use super::{downloads, visits};

/// True for the pages the window draws itself as a header over a list.
pub fn is_list(page: Page) -> bool {
    matches!(page, Page::Tabs | Page::Bookmarks | Page::Downloads | Page::History)
}

/// Indices into `shell.visits` the History page lists, newest first.
pub fn history_rows(shell: &Shell) -> Vec<usize> {
    visits::filter(&shell.visits, shell.hist_filter)
}

/// Indices into `shell.bookmarks`, newest first.
pub fn bookmark_rows(shell: &Shell) -> Vec<usize> {
    (0..shell.bookmarks.len()).rev().collect()
}

/// Indices into `shell.downloads` the Downloads page lists, newest first.
pub fn download_rows(shell: &Shell) -> Vec<usize> {
    downloads::filter(&shell.downloads, shell.dl_filter)
}

/// How many rows the list page shows now; zero for a page that is not one.
pub fn row_count(shell: &Shell) -> usize {
    match shell.page {
        Page::History => history_rows(shell).len(),
        Page::Bookmarks => shell.bookmarks.len(),
        Page::Downloads => download_rows(shell).len(),
        _ => 0,
    }
}
