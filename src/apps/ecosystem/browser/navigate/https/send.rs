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
use alloc::format;
use core::sync::atomic::Ordering;
use crate::network::stack::async_ops::tcp_send;
use crate::apps::ecosystem::browser::session;
use super::super::state::*;

pub(in crate::apps::ecosystem::browser::navigate) fn poll_send_request() {
    crate::network::poll_network();
    let host = match PENDING_HOST.lock().clone() { Some(h) => h, None => { cleanup_https(); finish_with_error("no host"); return; } };
    let path = PENDING_PATH.lock().clone().unwrap_or_else(|| String::from("/"));
    let method = PENDING_METHOD.lock().clone().unwrap_or_else(|| String::from("GET"));
    let body = PENDING_BODY.lock().clone();
    let content_type = PENDING_CONTENT_TYPE.lock().clone();
    let mut request = format!("{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: text/html,*/*\r\nAccept-Encoding: identity\r\nAccept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: close\r\n", method, path, host);
    if let Some(ref ct) = content_type { request.push_str(&format!("Content-Type: {}\r\n", ct)); }
    if let Some(sess) = session::get_active_session() {
        let cookies = sess.get_cookies(&host, &path);
        if !cookies.is_empty() {
            let cookie_str: String = cookies.iter().map(|c| c.to_header_value()).collect::<alloc::vec::Vec<_>>().join("; ");
            request.push_str(&format!("Cookie: {}\r\n", cookie_str));
        }
    }
    if let Some(ref b) = body { request.push_str(&format!("Content-Length: {}\r\n", b.len())); }
    request.push_str("\r\n");
    if let Some(ref b) = body { request.push_str(core::str::from_utf8(b).unwrap_or("")); }
    let mut tls_guard = HTTPS_TLS.lock();
    let tls = match tls_guard.as_mut() { Some(t) => t, None => { drop(tls_guard); cleanup_https(); finish_with_error("no TLS session"); return; } };
    let encrypted = match tls.encrypt_app(request.as_bytes()) { Ok(data) => data, Err(_) => { drop(tls_guard); cleanup_https(); finish_with_error("TLS encrypt failed"); return; } };
    drop(tls_guard);
    let wrapped = wrap_tls_record(0x17, &encrypted);
    crate::sys::serial::print(b"[HTTPS] sending request, wrapped_len=");
    crate::sys::serial::print_dec(wrapped.len() as u64);
    crate::sys::serial::println(b"");
    match tcp_send(&wrapped) {
        Ok(n) => { crate::sys::serial::print(b"[HTTPS] tcp_send ok, sent="); crate::sys::serial::print_dec(n as u64); crate::sys::serial::println(b""); }
        Err(e) => { crate::sys::serial::print(b"[HTTPS] tcp_send failed: "); crate::sys::serial::println(e.as_bytes()); cleanup_https(); finish_with_error("TCP send failed"); return; }
    }
    crate::network::poll_network();
    HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 15000, Ordering::Relaxed);
    set_state(NavState::ReceivingResponse);
}

fn wrap_tls_record(content_type: u8, data: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + data.len());
    record.push(content_type);
    record.push(0x03);
    record.push(0x03);
    record.push((data.len() >> 8) as u8);
    record.push((data.len() & 0xff) as u8);
    record.extend_from_slice(data);
    record
}
