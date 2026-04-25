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
use super::super::state;
use super::types::BrowserTab;
use alloc::vec::Vec;

pub fn create_tab(url: &str) -> u32 {
    let id = state::allocate_tab_id();
    state::add_tab(BrowserTab::new(id, url));
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
        let remaining = state::get_all_tabs();
        if !remaining.is_empty() {
            state::set_active_tab(remaining[0].id);
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
    state::get_tab(state::get_active_tab_id())
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
    let idx = tabs.iter().position(|t| t.id == state::get_active_tab_id()).unwrap_or(0);
    state::set_active_tab(tabs[(idx + 1) % tabs.len()].id);
}

pub fn prev_tab() {
    let tabs = state::get_all_tabs();
    if tabs.len() < 2 {
        return;
    }
    let idx = tabs.iter().position(|t| t.id == state::get_active_tab_id()).unwrap_or(0);
    state::set_active_tab(tabs[if idx == 0 { tabs.len() - 1 } else { idx - 1 }].id);
}
