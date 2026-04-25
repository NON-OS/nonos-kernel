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
use crate::network::onion::tls::TLSConnection;
use crate::network::stack::async_ops::tcp_close;
use crate::network::tcp::TcpSocket as TcpSocketWrapper;
use core::sync::atomic::Ordering;

pub(super) fn start_tls_handshake() {
    crate::sys::serial::println(b"[HTTPS] start_tls_handshake()");
    let conn_id = HTTPS_CONN_ID.load(Ordering::Relaxed);
    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            tcp_close();
            finish_with_error("no host");
            return;
        }
    };
    let socket = TcpSocketWrapper::from_connection(conn_id);
    let mut tls = TLSConnection::new();
    if let Err(_) = tls.start_handshake(&socket, Some(&host), Some(&["http/1.1"])) {
        crate::sys::serial::println(b"[HTTPS] tls.start_handshake FAILED");
        tcp_close();
        finish_with_error("TLS start failed");
        return;
    }
    *HTTPS_TLS.lock() = Some(tls);
    crate::sys::serial::println(b"[HTTPS] TLS handshake started, state=TlsHandshake");
    set_state(NavState::TlsHandshake);
}

pub(in crate::apps::ecosystem::browser::navigate) fn poll_tls_handshake() {
    let deadline = HTTPS_DEADLINE.load(Ordering::Relaxed);
    if crate::time::timestamp_millis() > deadline {
        cleanup_https();
        finish_with_error("TLS handshake timeout");
        return;
    }
    crate::network::poll_network();
    let conn_id = HTTPS_CONN_ID.load(Ordering::Relaxed);
    let socket = TcpSocketWrapper::from_connection(conn_id);
    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            cleanup_https();
            finish_with_error("no host");
            return;
        }
    };
    let verifier = crate::network::onion::tls::get_cert_verifier()
        .unwrap_or(&crate::network::onion::tls::HTTPS_CERT_VERIFIER);
    let mut tls_guard = HTTPS_TLS.lock();
    let tls = match tls_guard.as_mut() {
        Some(t) => t,
        None => {
            drop(tls_guard);
            cleanup_https();
            finish_with_error("no TLS context");
            return;
        }
    };
    match tls.poll_handshake(&socket, Some(&host), verifier) {
        Ok(Some(_)) => {
            drop(tls_guard);
            set_state(NavState::SendingRequest);
        }
        Ok(None) => {}
        Err(_) => {
            drop(tls_guard);
            cleanup_https();
            finish_with_error("TLS handshake failed");
        }
    }
}
