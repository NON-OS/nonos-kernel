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
use alloc::format;
use crate::network::stack::async_ops::{http_start_request, http_poll, AsyncResult};
use crate::apps::ecosystem::browser::session;
use super::state::*;
use super::compression;

pub(super) fn start_http_connection(ip: [u8; 4], port: u16) {
    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            finish_with_error("no host");
            return;
        }
    };

    let path = PENDING_PATH.lock().clone().unwrap_or_else(|| String::from("/"));
    let method = PENDING_METHOD.lock().clone().unwrap_or_else(|| String::from("GET"));
    let body = PENDING_BODY.lock().clone();
    let content_type = PENDING_CONTENT_TYPE.lock().clone();
    let accept_encoding = compression::accept_encoding_header();

    let mut request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: text/html,*/*\r\nAccept-Encoding: {}\r\nConnection: close\r\n",
        method, path, host, accept_encoding
    );
    if let Some(ref ct) = content_type {
        request.push_str(&format!("Content-Type: {}\r\n", ct));
    }
    if let Some(sess) = session::get_active_session() {
        let cookies = sess.get_cookies(&host, &path);
        if !cookies.is_empty() {
            let cookie_str: String = cookies.iter().map(|c| c.to_header_value()).collect::<alloc::vec::Vec<_>>().join("; ");
            request.push_str(&format!("Cookie: {}\r\n", cookie_str));
        }
    }
    if let Some(ref b) = body {
        request.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    if let Some(b) = body {
        bytes.extend_from_slice(&b);
    }

    match http_start_request(ip, port, bytes) {
        Ok(()) => {
            crate::sys::serial::println(b"[HTTP] request started, state=Connecting");
            set_state(NavState::Connecting);
        }
        Err(e) => {
            crate::sys::serial::print(b"[HTTP] start failed: ");
            crate::sys::serial::println(e.as_bytes());
            finish_with_error(e);
        }
    }
}

pub(super) fn poll_http_connection() {
    // Drive the network stack so TCP handshake / data frames are processed.
    crate::network::poll_network();

    match http_poll() {
        AsyncResult::Ready(data) => {
            crate::sys::serial::print(b"[HTTP] response ready, len=");
            crate::sys::serial::print_dec(data.len() as u64);
            crate::sys::serial::println(b"");
            *RESPONSE_DATA.lock() = data;
            set_state(NavState::ProcessingResponse);
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[HTTP] poll error: ");
            crate::sys::serial::println(e.as_bytes());
            finish_with_error(e);
        }
    }
}
