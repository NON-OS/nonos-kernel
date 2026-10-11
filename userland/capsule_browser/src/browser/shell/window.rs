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

use super::types::{Bookmark, Page, Visit};
use crate::browser::ui::layout::SidebarMode;

/// State that belongs to the window rather than to the page it shows.
#[derive(Default)]
pub struct Shell {
    pub sidebar: SidebarMode,
    pub page: Page,
    pub visits: Vec<Visit>,
    pub bookmarks: Vec<Bookmark>,
    pub page_scroll: i32,
    /* Tabs open in the window, as the start page counts them. */
    pub tabs: usize,
}

impl Shell {
    /// True when the content area shows the start page: asked for outright,
    /// or the web view of a tab that has not loaded anything yet.
    pub fn showing_start(&self, tab_home: bool) -> bool {
        self.page == Page::Start || (self.page == Page::Web && tab_home)
    }

    /// Shows `page` from its top.
    pub fn show(&mut self, page: Page) {
        self.page = page;
        self.page_scroll = 0;
    }
}
