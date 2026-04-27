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

use super::super::state::*;
use super::handshake::start_tls_handshake;
use crate::network::stack::async_ops::{
    tcp_close, tcp_poll_connect, tcp_start_connect, AsyncResult,
};
use core::sync::atomic::Ordering;

pub(in crate::apps::ecosystem::browser::navigate) fn start_https_connection(
    ip: [u8; 4],
    port: u16,
) {
    match tcp_start_connect(ip, port) {
        Ok(conn_id) => {
            crate::sys::serial::print(b"[HTTPS] TCP connect started, id=");
            crate::sys::serial::print_dec(conn_id as u64);
            crate::sys::serial::println(b"");
            HTTPS_CONN_ID.store(conn_id, Ordering::Relaxed);
            HTTPS_DEADLINE.store(crate::time::timestamp_millis() + 20000, Ordering::Relaxed);
            set_state(NavState::Connecting);
        }
        Err(e) => {
            crate::sys::serial::print(b"[HTTPS] TCP start failed: ");
            crate::sys::serial::println(e.as_bytes());
            finish_with_error(e);
        }
    }
}

pub(in crate::apps::ecosystem::browser::navigate) fn poll_tcp_connect() {
    crate::network::poll_network();
    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    let now = crate::time::timestamp_millis();
    if now > deadline {
        crate::sys::serial::println(b"[HTTPS] TCP connect deadline exceeded");
        tcp_close();
        finish_with_error("TCP connect timeout");
        return;
    }
    match tcp_poll_connect() {
        AsyncResult::Ready(()) => {
            crate::sys::serial::println(b"[HTTPS] TCP connected, starting TLS");
            start_tls_handshake();
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[HTTPS] tcp_poll_connect error: ");
            crate::sys::serial::println(e.as_bytes());
            finish_with_error(e);
        }
    }
}
