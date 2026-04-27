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

use super::body::{extract_body, extract_title};
use super::redirect::extract_redirect;
use super::render::render_page;
use crate::apps::ecosystem::browser::engine;
use crate::apps::ecosystem::browser::history::add_history;
use crate::apps::ecosystem::browser::navigate::state::*;
use crate::apps::ecosystem::browser::tabs::active_tab;
use crate::graphics::window::ecosystem::state as window_state;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub(crate) fn process_response() {
    let response_data = RESPONSE_DATA.lock().clone();
    crate::sys::serial::print(b"[NAV] process_response len=");
    crate::sys::serial::print_dec(response_data.len() as u64);
    crate::sys::serial::println(b"");
    let url = PENDING_URL.lock().clone().unwrap_or_default();
    if let Some(redirect_url) = extract_redirect(&response_data, &url) {
        let count = REDIRECT_COUNT.load(Ordering::Relaxed);
        if count < MAX_REDIRECTS {
            crate::sys::serial::print(b"[NAV] redirect -> ");
            crate::sys::serial::println(redirect_url.as_bytes());
            REDIRECT_COUNT.fetch_add(1, Ordering::Relaxed);
            cleanup_navigation();
            set_state(NavState::Done);
            crate::apps::ecosystem::browser::navigate::api::navigate_internal(&redirect_url);
            return;
        }
        crate::sys::serial::println(b"[NAV] too many redirects");
    }
    REDIRECT_COUNT.store(0, Ordering::Relaxed);
    let body = extract_body(&response_data);
    crate::sys::serial::print(b"[NAV] body len=");
    crate::sys::serial::print_dec(body.len() as u64);
    crate::sys::serial::println(b"");
    window_state::set_base_url(&url);
    window_state::clear_page_links();
    if let Some(tab) = active_tab() {
        let mut tab = tab;
        tab.url = url.clone();
        tab.content = body.clone();
        let title = extract_title(&body).unwrap_or_else(|| String::from("Untitled"));
        tab.title = title.clone();
        add_history(&url, &title);
    }
    let content_str = core::str::from_utf8(&body).unwrap_or("");
    engine::image_loader::disable_fetch();
    crate::sys::serial::println(b"[NAV] rendering page...");
    render_page(content_str, &url, &body);
}
