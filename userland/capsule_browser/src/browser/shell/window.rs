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

use super::cards::TabCard;
use super::kept::{Appearance, Group, ReaderPrefs};
use super::settings_ui::SettingsUi;
use super::types::{Bookmark, Download, Page, PendingSave, Visit};
use crate::browser::reader::extract::Article;
use crate::browser::ui::layout::SidebarMode;

/// State that belongs to the window rather than to the page it shows.
#[derive(Default)]
pub struct Shell {
    pub sidebar: SidebarMode,
    pub page: Page,
    pub visits: Vec<Visit>,
    pub bookmarks: Vec<Bookmark>,
    pub page_scroll: i32,
    /* The open tabs, as the start page counts them and the Tabs page and
     * the sidebar draw them. */
    pub cards: Vec<TabCard>,
    /* Bookmarks this window took out, so a merge with another window's
     * save does not bring them back. */
    pub removed_bookmarks: Vec<String>,
    /* This session's downloads, and the bodies still waiting to be saved. */
    pub downloads: Vec<Download>,
    pub saving: Vec<PendingSave>,
    /* The window's tab groups, the one the Tabs page is filtered to, and
     * the name being typed over it while it is renamed. */
    pub groups: Vec<Group>,
    pub group_filter: Option<u8>,
    pub rename: Option<String>,
    pub removed_groups: Vec<u8>,
    /* The History and Downloads filter pills in force. */
    pub hist_filter: u8,
    pub dl_filter: u8,
    /* The reader's settings, and the article it shows. */
    pub reader: ReaderPrefs,
    pub article: Option<Article>,
    /* Light or dark chrome, kept across runs with the bookmarks. */
    pub appearance: Appearance,
    /* The custom search template, kept with the bookmarks; None searches
     * the default engine. */
    pub search: Option<String>,
    pub settings: SettingsUi,
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
        self.rename = None;
        self.settings.settle();
    }

    /// True when the content area shows a page the window draws itself
    /// rather than the tab's own: the start page, a list page or the reader.
    pub fn own_page(&self, tab_home: bool) -> bool {
        self.page != Page::Web || tab_home
    }
}
