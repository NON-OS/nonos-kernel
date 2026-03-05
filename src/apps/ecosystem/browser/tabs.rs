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

use alloc::string::String;
use alloc::vec::Vec;

use super::state;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabStatus {
    Loading,
    Ready,
    Error,
    Blank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatus {
    Secure,
    Insecure,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct BrowserTab {
    pub id: u32,
    pub url: String,
    pub title: String,
    pub content: Vec<u8>,
    pub status: TabStatus,
    pub security: SecurityStatus,
    pub can_go_back: bool,
    pub can_go_forward: bool,
    pub scroll_position: u32,
    pub favicon: Option<Vec<u8>>,
    pub error_message: Option<String>,
    history_index: usize,
    history: Vec<String>,
}

impl BrowserTab {
    pub fn new(id: u32, url: &str) -> Self {
        let status = if url == "about:blank" {
            TabStatus::Blank
        } else {
            TabStatus::Loading
        };

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

    fn update_navigation_state(&mut self) {
        self.can_go_back = self.history_index > 0;
        self.can_go_forward = self.history_index < self.history.len() - 1;
    }

    pub fn domain(&self) -> Option<String> {
        let url = &self.url;

        let start = if url.starts_with("https://") {
            8
        } else if url.starts_with("http://") {
            7
        } else {
            return None;
        };

        let rest = &url[start..];
        let end = rest.find('/').unwrap_or(rest.len());
        let domain = &rest[..end];

        let domain = if let Some(at_pos) = domain.find('@') {
            &domain[at_pos + 1..]
        } else {
            domain
        };

        let domain = if let Some(colon_pos) = domain.find(':') {
            &domain[..colon_pos]
        } else {
            domain
        };

        Some(String::from(domain))
    }

    pub fn is_secure(&self) -> bool {
        self.security == SecurityStatus::Secure
    }
}

pub fn create_tab(url: &str) -> u32 {
    let id = state::allocate_tab_id();
    let tab = BrowserTab::new(id, url);
    state::add_tab(tab);
    id
}

pub fn close_tab(id: u32) -> bool {
    let tabs = state::get_all_tabs();

    if tabs.len() <= 1 {
        return false;
    }

    let current_active = state::get_active_tab_id();

    if !state::remove_tab(id) {
        return false;
    }

    if current_active == id {
        let remaining_tabs = state::get_all_tabs();
        if !remaining_tabs.is_empty() {
            state::set_active_tab(remaining_tabs[0].id);
        }
    }

    true
}

pub fn switch_tab(id: u32) -> bool {
    if state::get_tab(id).is_some() {
        state::set_active_tab(id);
        true
    } else {
        false
    }
}

pub fn active_tab() -> Option<BrowserTab> {
    let id = state::get_active_tab_id();
    state::get_tab(id)
}

pub fn get_tabs() -> Vec<BrowserTab> {
    state::get_all_tabs()
}

pub fn navigate_tab(id: u32, url: &str) {
    state::update_tab(id, |tab| {
        tab.navigate(url);
    });
}

pub fn go_back_tab(id: u32) -> bool {
    let mut success = false;
    state::update_tab(id, |tab| {
        success = tab.go_back();
    });
    success
}

pub fn go_forward_tab(id: u32) -> bool {
    let mut success = false;
    state::update_tab(id, |tab| {
        success = tab.go_forward();
    });
    success
}

pub fn reload_tab(id: u32) {
    state::update_tab(id, |tab| {
        tab.reload();
    });
}

pub fn stop_tab(id: u32) {
    state::update_tab(id, |tab| {
        tab.stop();
    });
}

pub fn set_tab_ready(id: u32, title: &str) {
    state::update_tab(id, |tab| {
        tab.set_ready(title);
    });
}

pub fn set_tab_error(id: u32, message: &str) {
    state::update_tab(id, |tab| {
        tab.set_error(message);
    });
}

pub fn get_tab_count() -> usize {
    state::get_all_tabs().len()
}

pub fn next_tab() {
    let tabs = state::get_all_tabs();
    if tabs.len() < 2 {
        return;
    }

    let current_id = state::get_active_tab_id();
    let current_idx = tabs.iter().position(|t| t.id == current_id).unwrap_or(0);
    let next_idx = (current_idx + 1) % tabs.len();
    state::set_active_tab(tabs[next_idx].id);
}

pub fn prev_tab() {
    let tabs = state::get_all_tabs();
    if tabs.len() < 2 {
        return;
    }

    let current_id = state::get_active_tab_id();
    let current_idx = tabs.iter().position(|t| t.id == current_id).unwrap_or(0);
    let prev_idx = if current_idx == 0 {
        tabs.len() - 1
    } else {
        current_idx - 1
    };
    state::set_active_tab(tabs[prev_idx].id);
}
