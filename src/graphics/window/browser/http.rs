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

use alloc::format;
use alloc::string::String;
use core::sync::atomic::Ordering;

use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::network::stack::async_ops;

use super::state::*;

pub(super) use super::http_nav::{go_back, go_forward, refresh, navigate};
pub use super::http_poll::poll_fetch;

pub(super) struct ParsedUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub is_https: bool,
}

pub(super) fn parse_url(url: &str) -> Option<ParsedUrl> {
    let url = url.trim();

    if url.is_empty() {
        return None;
    }

    let is_https = url.starts_with("https://");
    let default_port: u16 = if is_https { 443 } else { 80 };

    let url = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        &url[8..]
    } else {
        url
    };

    let (host_port, path) = if let Some(slash_pos) = url.find('/') {
        (&url[..slash_pos], String::from(&url[slash_pos..]))
    } else {
        (url, String::from("/"))
    };

    let (host, port) = if let Some(colon_pos) = host_port.find(':') {
        let h = &host_port[..colon_pos];
        let p: u16 = host_port[colon_pos + 1..].parse().unwrap_or(default_port);
        (h, p)
    } else {
        (host_port, default_port)
    };

    if host.is_empty() {
        return None;
    }

    let is_localhost = host == "localhost";
    let has_dot = host.contains('.');
    let is_ip = host.chars().all(|c| c.is_ascii_digit() || c == '.');

    if !is_localhost && !has_dot && !is_ip {
        return None;
    }

    Some(ParsedUrl {
        host: String::from(host),
        port,
        path,
        is_https,
    })
}

pub(super) fn fetch_page(url_str: &str) {
    let parsed = match parse_url(url_str) {
        Some(p) => p,
        None => {
            LOADING.store(false, Ordering::Relaxed);
            LOAD_ERROR.store(true, Ordering::Relaxed);
            set_status(b"Error: Invalid URL");
            show_error_page("Invalid URL format", &[
                &format!("'{}' is not a valid URL.", url_str),
                "",
                "Valid examples: example.com, http://site.com/path",
            ]);
            return;
        }
    };

    if !crate::network::is_network_available() {
        LOADING.store(false, Ordering::Relaxed);
        LOAD_ERROR.store(true, Ordering::Relaxed);
        set_status(b"Error: No network");
        show_error_page("No network connection", &[]);
        return;
    }

    {
        let mut url = FETCH_URL.lock();
        let len = url_str.len().min(511);
        url[..len].copy_from_slice(&url_str.as_bytes()[..len]);
        FETCH_URL_LEN.store(len, Ordering::Relaxed);
    }
    {
        let mut host = FETCH_HOST.lock();
        let len = parsed.host.len().min(255);
        host[..len].copy_from_slice(&parsed.host.as_bytes()[..len]);
        FETCH_HOST_LEN.store(len, Ordering::Relaxed);
    }
    {
        let mut path = FETCH_PATH.lock();
        let len = parsed.path.len().min(255);
        path[..len].copy_from_slice(&parsed.path.as_bytes()[..len]);
        FETCH_PATH_LEN.store(len, Ordering::Relaxed);
    }
    FETCH_PORT.store(parsed.port as usize, Ordering::Relaxed);
    FETCH_HTTPS.store(parsed.is_https, Ordering::Relaxed);

    LOADING.store(true, Ordering::Relaxed);
    LOAD_ERROR.store(false, Ordering::Relaxed);
    clear_page();
    set_status(b"Resolving DNS...");

    if let Err(e) = async_ops::dns_start_query(&parsed.host) {
        LOADING.store(false, Ordering::Relaxed);
        LOAD_ERROR.store(true, Ordering::Relaxed);
        set_status(format!("DNS error: {}", e).as_bytes());
        show_error_page("DNS lookup failed", &[e]);
        *FETCH_STATE.lock() = FetchState::Error;
        return;
    }

    *FETCH_STATE.lock() = FetchState::ResolvingDns;
    FETCH_START_MS.store(crate::time::timestamp_millis() as usize, Ordering::Relaxed);
}

fn show_error_page(title: &str, details: &[&str]) {
    let mut lines = PAGE_LINES.lock();
    lines.clear();
    lines.push((format!("Error: {}", title), COLOR_ACCENT));
    lines.push((String::new(), COLOR_TEXT_WHITE));
    for detail in details {
        lines.push((String::from(*detail), COLOR_TEXT_WHITE));
    }
}
