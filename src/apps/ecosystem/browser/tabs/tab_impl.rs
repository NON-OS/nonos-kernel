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
use super::types::{BrowserTab, SecurityStatus, TabStatus};
use alloc::string::String;
use alloc::vec::Vec;

impl BrowserTab {
    pub fn new(id: u32, url: &str) -> Self {
        let status = if url == "about:blank" { TabStatus::Blank } else { TabStatus::Loading };
        Self {
            id,
            url: String::from(url),
            title: String::from("New Tab"),
            content: Vec::new(),
            status,
            security: SecurityStatus::Unknown,
            can_go_back: false,
            can_go_forward: false,
            scroll_position: 0,
            favicon: None,
            error_message: None,
            history_index: 0,
            history: alloc::vec![String::from(url)],
        }
    }

    pub fn navigate(&mut self, url: &str) {
        if self.history_index < self.history.len() - 1 {
            self.history.truncate(self.history_index + 1);
        }
        self.history.push(String::from(url));
        self.history_index = self.history.len() - 1;
        self.url = String::from(url);
        self.status = TabStatus::Loading;
        self.scroll_position = 0;
        self.error_message = None;
        self.update_navigation_state();
        self.security = if url.starts_with("https://") {
            SecurityStatus::Secure
        } else if url.starts_with("http://") {
            SecurityStatus::Insecure
        } else {
            SecurityStatus::Unknown
        };
    }

    pub fn go_back(&mut self) -> bool {
        if self.history_index > 0 {
            self.history_index -= 1;
            self.url = self.history[self.history_index].clone();
            self.status = TabStatus::Loading;
            self.scroll_position = 0;
            self.update_navigation_state();
            true
        } else {
            false
        }
    }
    pub fn go_forward(&mut self) -> bool {
        if self.history_index < self.history.len() - 1 {
            self.history_index += 1;
            self.url = self.history[self.history_index].clone();
            self.status = TabStatus::Loading;
            self.scroll_position = 0;
            self.update_navigation_state();
            true
        } else {
            false
        }
    }
    pub fn reload(&mut self) {
        self.status = TabStatus::Loading;
        self.scroll_position = 0;
        self.error_message = None;
    }
    pub fn stop(&mut self) {
        if self.status == TabStatus::Loading {
            self.status = TabStatus::Ready;
        }
    }
    pub fn set_ready(&mut self, title: &str) {
        self.title = String::from(title);
        self.status = TabStatus::Ready;
    }
    pub fn set_error(&mut self, message: &str) {
        self.status = TabStatus::Error;
        self.error_message = Some(String::from(message));
    }
    pub fn set_favicon(&mut self, favicon: Vec<u8>) {
        self.favicon = Some(favicon);
    }
    pub(super) fn update_navigation_state(&mut self) {
        self.can_go_back = self.history_index > 0;
        self.can_go_forward = self.history_index < self.history.len() - 1;
    }

    pub fn domain(&self) -> Option<String> {
        let start = if self.url.starts_with("https://") {
            8
        } else if self.url.starts_with("http://") {
            7
        } else {
            return None;
        };
        let rest = &self.url[start..];
        let end = rest.find('/').unwrap_or(rest.len());
        let domain = &rest[..end];
        let domain = if let Some(at) = domain.find('@') { &domain[at + 1..] } else { domain };
        let domain = if let Some(colon) = domain.find(':') { &domain[..colon] } else { domain };
        Some(String::from(domain))
    }

    pub fn is_secure(&self) -> bool {
        self.security == SecurityStatus::Secure
    }
}
