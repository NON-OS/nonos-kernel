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

extern crate alloc;

use super::global::SESSION_ID_COUNTER;
use super::types::{BrowserSession, SessionStorage, SessionTab};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl BrowserSession {
    pub fn new(name: &str, is_private: bool) -> Self {
        let id = SESSION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = crate::time::timestamp_secs();
        Self {
            id,
            name: String::from(name),
            created_at: now,
            last_active: now,
            is_private,
            tabs: Vec::new(),
            storage: SessionStorage::default(),
        }
    }

    pub fn add_tab(&mut self, url: &str, title: &str) {
        self.tabs.push(SessionTab {
            url: String::from(url),
            title: String::from(title),
            scroll_position: 0,
        });
        self.touch();
    }

    pub fn remove_tab(&mut self, index: usize) -> bool {
        if index < self.tabs.len() {
            self.tabs.remove(index);
            self.touch();
            true
        } else {
            false
        }
    }

    pub fn update_tab(&mut self, index: usize, url: &str, title: &str) {
        if let Some(tab) = self.tabs.get_mut(index) {
            tab.url = String::from(url);
            tab.title = String::from(title);
            self.touch();
        }
    }

    pub fn touch(&mut self) {
        self.last_active = crate::time::timestamp_secs();
    }

    pub fn clear_all_storage(&mut self) {
        self.storage.cookies.clear();
        self.storage.local_storage.clear();
        self.storage.session_storage.clear();
    }
}
