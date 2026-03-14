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
use core::sync::atomic::Ordering;
use crate::graphics::window::ecosystem::state as window_state;
use super::super::engine;
use super::super::history::add_history;
use super::super::tabs::active_tab;
use super::state::*;

pub(super) fn process_response() {
    use crate::sys::serial;

    let response_data = RESPONSE_DATA.lock().clone();
    let url = PENDING_URL.lock().clone().unwrap_or_default();

    serial::print(b"[BROWSER] processing response: ");
    serial::print_dec(response_data.len() as u64);
    serial::println(b" bytes");

    let body = extract_body(&response_data);
    serial::print(b"[BROWSER] body size: ");
    serial::print_dec(body.len() as u64);
    serial::println(b" bytes");

    window_state::set_base_url(&url);
    window_state::clear_page_links();

    if let Some(tab) = active_tab() {
        let mut tab = tab;
        tab.url = url.clone();
        tab.content = body.clone();
        let title = extract_title(&body).unwrap_or_else(|| String::from("Untitled"));
        serial::print(b"[BROWSER] title: ");
        let title_bytes = title.as_bytes();
        let display_len = title_bytes.len().min(50);
        serial::print(&title_bytes[..display_len]);
        serial::println(b"");
        tab.title = title.clone();
        add_history(&url, &title);
    }

    let content_str = core::str::from_utf8(&body).unwrap_or("");
    let (lines, links) = engine::render_to_lines_with_links(content_str);

    serial::print(b"[BROWSER] rendered ");
    serial::print_dec(lines.len() as u64);
    serial::print(b" lines, ");
    serial::print_dec(links.len() as u64);
    serial::println(b" links");

    for (line_idx, start_x, end_x, href) in links {
        window_state::add_page_link(line_idx, start_x, end_x, &href);
    }

    let title = extract_title(&body).unwrap_or_else(|| String::from("Untitled"));
    window_state::set_page_title(&title);

    {
        let mut page_content = window_state::PAGE_CONTENT.lock();
        page_content.clear();
        window_state::PAGE_TOTAL_LINES.store(lines.len(), core::sync::atomic::Ordering::Relaxed);
        page_content.extend(lines);
    }
    window_state::PAGE_SCROLL.store(0, Ordering::Relaxed);
    window_state::LOADING.store(false, Ordering::Relaxed);
    window_state::mark_content_changed();

    cleanup_navigation();
    set_state(NavState::Done);
    serial::println(b"[BROWSER] page loaded successfully");
}

pub(super) fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i);
        }
    }
    None
}

pub(super) fn is_response_complete(data: &[u8]) -> bool {
    if let Some(header_end) = find_header_end(data) {
        let headers = &data[..header_end];
        let body_start = header_end + 4;
        let body_len = data.len() - body_start;

        if let Some(cl) = parse_content_length(headers) {
            return body_len >= cl;
        }
    }
    false
}

const MAX_CONTENT_LENGTH: usize = 16 * 1024 * 1024;

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let s = core::str::from_utf8(headers).ok()?;
    for line in s.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            let val = line[15..].trim();
            let len: usize = val.parse().ok()?;
            if len > MAX_CONTENT_LENGTH {
                return None;
            }
            return Some(len);
        }
    }
    None
}

fn extract_body(data: &[u8]) -> Vec<u8> {
    if let Some(header_end) = find_header_end(data) {
        Vec::from(&data[header_end + 4..])
    } else {
        Vec::from(data)
    }
}

fn extract_title(body: &[u8]) -> Option<String> {
    let html = core::str::from_utf8(body).ok()?;
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start..].find("</title>")?;
    let title = &html[start + 7..start + end];
    Some(String::from(title.trim()))
}
