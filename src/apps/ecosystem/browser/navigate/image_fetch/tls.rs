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

use super::connect::img_cleanup;
use super::queue::skip_current_image;
use super::types::*;
use crate::network::onion::tls::TLSConnection;
use crate::network::tcp::TcpSocket as TcpSocketWrapper;
use core::sync::atomic::Ordering;

pub(super) fn start_img_tls() {
    let conn_id = IMG_CONN_ID.load(Ordering::Relaxed);
    let host = match IMG_HOST.lock().clone() {
        Some(h) => h,
        None => {
            img_cleanup();
            skip_current_image();
            return;
        }
    };
    let socket = TcpSocketWrapper::from_connection(conn_id);
    let mut tls = TLSConnection::new();
    if tls.start_handshake(&socket, Some(&host), Some(&["http/1.1"])).is_err() {
        crate::sys::serial::println(b"[IMG-FETCH] TLS start failed");
        img_cleanup();
        skip_current_image();
        return;
    }
    *IMG_TLS.lock() = Some(tls);
    set_img_state(ImgFetchState::TlsHandshake);
}

pub(super) fn poll_img_tls() {
    if is_timed_out() {
        crate::sys::serial::println(b"[IMG-FETCH] TLS timeout");
        img_cleanup();
        skip_current_image();
        return;
    }
    crate::network::poll_network();
    let conn_id = IMG_CONN_ID.load(Ordering::Relaxed);
    let socket = TcpSocketWrapper::from_connection(conn_id);
    let host = match IMG_HOST.lock().clone() {
        Some(h) => h,
        None => {
            img_cleanup();
            skip_current_image();
            return;
        }
    };
    let verifier = crate::network::onion::tls::get_cert_verifier()
        .unwrap_or(&crate::network::onion::tls::HTTPS_CERT_VERIFIER);
    let mut tls_guard = IMG_TLS.lock();
    let tls = match tls_guard.as_mut() {
        Some(t) => t,
        None => {
            drop(tls_guard);
            img_cleanup();
            skip_current_image();
            return;
        }
    };
    match tls.poll_handshake(&socket, Some(&host), verifier) {
        Ok(Some(_)) => {
            drop(tls_guard);
            crate::sys::serial::println(b"[IMG-FETCH] TLS done");
            set_img_state(ImgFetchState::Sending);
        }
        Ok(None) => {}
        Err(_) => {
            drop(tls_guard);
            crate::sys::serial::println(b"[IMG-FETCH] TLS handshake failed");
            img_cleanup();
            skip_current_image();
        }
    }
}
