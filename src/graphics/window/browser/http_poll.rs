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
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::graphics::framebuffer::{COLOR_ACCENT, COLOR_TEXT_WHITE};
use crate::network::stack::async_ops::{self, AsyncResult};

use super::state::*;
use super::html::parse_html;
use super::http_nav::add_to_history;

pub fn poll_fetch() -> bool {
    let state = *FETCH_STATE.lock();

    match state {
        FetchState::Idle | FetchState::Done | FetchState::Error => false,

        FetchState::ResolvingDns => {
            match async_ops::dns_poll() {
                AsyncResult::Pending => true,
                AsyncResult::Ready(ip) => {
                    *FETCH_IP.lock() = ip;
                    let is_https = FETCH_HTTPS.load(Ordering::Relaxed);

                    if is_https {
                        set_status(b"Establishing secure connection...");
                        let port = FETCH_PORT.load(Ordering::Relaxed) as u16;
                        let host = get_host_string();
                        let path = get_path_string();
                        let request = build_request(&host, &path);

                        if let Some(ns) = crate::network::get_network_stack() {
                            match ns.https_request(ip, port, &host, &request, 30_000) {
                                Ok(response) => {
                                    if let Some(body) = extract_body(&response) {
                                        process_response(body, &host, response.len(), true);
                                        *FETCH_STATE.lock() = FetchState::Done;
                                    } else {
                                        finish_with_error("Invalid HTTPS response");
                                    }
                                }
                                Err(e) => {
                                    finish_with_error(e);
                                }
                            }
                        } else {
                            finish_with_error("No network stack");
                        }
                        false
                    } else {
                        set_status(b"Connecting...");
                        let port = FETCH_PORT.load(Ordering::Relaxed) as u16;
                        let host = get_host_string();
                        let path = get_path_string();
                        let request = build_request(&host, &path);

                        match async_ops::http_start_request(ip, port, request) {
                            Ok(()) => {
                                *FETCH_STATE.lock() = FetchState::Connecting;
                                true
                            }
                            Err(e) => {
                                finish_with_error(e);
                                false
                            }
                        }
                    }
                }
                AsyncResult::Error(e) => {
                    finish_with_error(e);
                    false
                }
            }
        }

        FetchState::Connecting => {
            *FETCH_STATE.lock() = FetchState::Fetching;
            true
        }

        FetchState::Fetching => {
            match async_ops::http_poll() {
                AsyncResult::Pending => true,
                AsyncResult::Ready(response) => {
                    if let Some(body) = extract_body(&response) {
                        set_status(b"Parsing response...");
                        *FETCH_STATE.lock() = FetchState::Parsing;
                        let host = get_host_string();
                        process_response(body, &host, response.len(), false);
                        *FETCH_STATE.lock() = FetchState::Done;
                    } else {
                        finish_with_error("Invalid HTTP response");
                    }
                    false
                }
                AsyncResult::Error(e) => {
                    finish_with_error(e);
                    false
                }
            }
        }

        FetchState::Parsing => {
            *FETCH_STATE.lock() = FetchState::Done;
            false
        }
    }
}

fn process_response(body: &[u8], host: &str, len: usize, is_https: bool) {
    let parsed_lines = parse_html(body);
    {
        let mut lines = PAGE_LINES.lock();
        lines.clear();
        for (text, color) in parsed_lines {
            lines.push((text, color));
        }
    }

    let url = {
        let u = FETCH_URL.lock();
        let len = FETCH_URL_LEN.load(Ordering::Relaxed);
        core::str::from_utf8(&u[..len]).unwrap_or("").to_string()
    };
    add_to_history(&url);

    LOADING.store(false, Ordering::Relaxed);
    let proto = if is_https { "HTTPS" } else { "HTTP" };
    let status = format!("Loaded: {} ({}, {} bytes)", host, proto, len);
    set_status(status.as_bytes());
}

fn get_host_string() -> String {
    let h = FETCH_HOST.lock();
    let len = FETCH_HOST_LEN.load(Ordering::Relaxed);
    core::str::from_utf8(&h[..len]).unwrap_or("").to_string()
}

fn get_path_string() -> String {
    let p = FETCH_PATH.lock();
    let len = FETCH_PATH_LEN.load(Ordering::Relaxed);
    core::str::from_utf8(&p[..len]).unwrap_or("/").to_string()
}

fn finish_with_error(msg: &str) {
    LOADING.store(false, Ordering::Relaxed);
    LOAD_ERROR.store(true, Ordering::Relaxed);
    set_status(format!("Error: {}", msg).as_bytes());
    show_error_page(msg, &[]);
    *FETCH_STATE.lock() = FetchState::Error;
}

pub(super) fn build_request(host: &str, path: &str) -> Vec<u8> {
    let mut req = Vec::new();
    req.extend_from_slice(b"GET ");
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(b"\r\nUser-Agent: NONOS/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    req
}

fn extract_body(response: &[u8]) -> Option<&[u8]> {
    for i in 0..response.len().saturating_sub(3) {
        if &response[i..i + 4] == b"\r\n\r\n" {
            return Some(&response[i + 4..]);
        }
    }
    None
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
