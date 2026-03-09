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
use core::sync::atomic::{AtomicBool, Ordering};

use crate::graphics::window::ecosystem::state as window_state;
use super::engine;
use super::history::add_history;
use super::request::{fetch_page, FetchError, FetchOptions};
use super::tabs::active_tab;

static RUNNING: AtomicBool = AtomicBool::new(false);

pub fn start() {
    RUNNING.store(true, Ordering::SeqCst);
}

pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}

pub fn navigate(url: &str) {
    window_state::LOADING.store(true, Ordering::Relaxed);
    window_state::clear_error();

    let options = FetchOptions::default();
    match fetch_page(url, options) {
        Ok(result) => {
            if let Some(tab) = active_tab() {
                let mut tab = tab;
                tab.url = String::from(url);
                tab.content = result.body.clone();
                let title = result.title.clone().unwrap_or_else(|| String::from("Untitled"));
                tab.title = title.clone();
                add_history(url, &title);
            }

            let content_str = core::str::from_utf8(&result.body).unwrap_or("");
            let lines: Vec<String> = engine::render_to_lines(content_str);

            {
                let mut page_content = window_state::PAGE_CONTENT.lock();
                page_content.clear();
                page_content.extend(lines);
            }
            window_state::PAGE_SCROLL.store(0, Ordering::Relaxed);
            window_state::mark_content_changed();
        }
        Err(e) => {
            let error_msg = match e {
                FetchError::NetworkError => "Network error",
                FetchError::DnsError => "DNS resolution failed",
                FetchError::TlsError => "TLS/SSL error",
                FetchError::Timeout => "Request timed out",
                FetchError::InvalidUrl => "Invalid URL",
                FetchError::Blocked => "Request blocked",
                FetchError::TooManyRedirects => "Too many redirects",
                FetchError::ConnectionRefused => "Connection refused",
                FetchError::InvalidResponse => "Invalid response",
                FetchError::HttpsRequired => "HTTPS required",
            };
            window_state::set_error(error_msg);
            window_state::mark_content_changed();
        }
    }

    window_state::LOADING.store(false, Ordering::Relaxed);
    window_state::mark_content_changed();
}
