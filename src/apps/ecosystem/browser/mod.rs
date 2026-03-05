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

//! NONOS Ecosystem Browser Module.

extern crate alloc;

pub mod engine;
pub mod history;
pub mod request;
pub mod session;
pub mod state;
pub mod tabs;

pub use engine::{render_page, BrowserEngine};
pub use history::{add_history, clear_history, get_history, HistoryEntry};
pub use request::{fetch_page, FetchOptions, FetchResult};
pub use session::{create_session, destroy_session, get_session, BrowserSession};
pub use state::{get_state, init, BrowserState};
pub use tabs::{active_tab, close_tab, create_tab, get_tabs, switch_tab, BrowserTab};

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

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
    use crate::graphics::window::ecosystem::state as window_state;
    use alloc::vec::Vec;

    window_state::LOADING.store(true, core::sync::atomic::Ordering::Relaxed);
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
            window_state::PAGE_SCROLL.store(0, core::sync::atomic::Ordering::Relaxed);
        }
        Err(e) => {
            let error_msg = match e {
                request::FetchError::NetworkError => "Network error",
                request::FetchError::DnsError => "DNS resolution failed",
                request::FetchError::TlsError => "TLS/SSL error",
                request::FetchError::Timeout => "Request timed out",
                request::FetchError::InvalidUrl => "Invalid URL",
                request::FetchError::Blocked => "Request blocked",
                request::FetchError::TooManyRedirects => "Too many redirects",
                request::FetchError::ConnectionRefused => "Connection refused",
                request::FetchError::InvalidResponse => "Invalid response",
                request::FetchError::HttpsRequired => "HTTPS required",
            };
            window_state::set_error(error_msg);
        }
    }

    window_state::LOADING.store(false, core::sync::atomic::Ordering::Relaxed);
}
