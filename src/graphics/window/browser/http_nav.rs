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
use core::sync::atomic::Ordering;

use super::state::*;
use super::http::fetch_page;

pub(super) fn add_to_history(url: &str) {
    let mut history = HISTORY.lock();
    let pos = HISTORY_POS.load(Ordering::Relaxed);
    if pos < history.len() {
        history.truncate(pos);
    }
    history.push(String::from(url));
    HISTORY_POS.store(history.len(), Ordering::Relaxed);
}

pub(super) fn go_back() {
    let history = HISTORY.lock();
    let pos = HISTORY_POS.load(Ordering::Relaxed);
    if pos > 1 {
        HISTORY_POS.store(pos - 1, Ordering::Relaxed);
        if let Some(url) = history.get(pos - 2) {
            let url_clone = url.clone();
            drop(history);
            set_url(&url_clone);
            fetch_page(&url_clone);
        }
    }
}

pub(super) fn go_forward() {
    let history = HISTORY.lock();
    let pos = HISTORY_POS.load(Ordering::Relaxed);
    if pos < history.len() {
        HISTORY_POS.store(pos + 1, Ordering::Relaxed);
        if let Some(url) = history.get(pos) {
            let url_clone = url.clone();
            drop(history);
            set_url(&url_clone);
            fetch_page(&url_clone);
        }
    }
}

pub(super) fn refresh() {
    if let Some(url) = get_url_string() {
        fetch_page(&url);
    }
}

pub(super) fn navigate() {
    if !LOADING.load(Ordering::Relaxed) {
        if let Some(url) = get_url_string() {
            fetch_page(&url);
        }
    }
}
