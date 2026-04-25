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

use super::body::wrap_tls_record;
use super::connect::img_cleanup;
use super::queue::skip_current_image;
use super::types::*;
use crate::network::stack::async_ops::tcp_send;
use alloc::format;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub(super) fn poll_img_send() {
    crate::network::poll_network();
    let host = match IMG_HOST.lock().clone() {
        Some(h) => h,
        None => {
            img_cleanup();
            skip_current_image();
            return;
        }
    };
    let path = IMG_PATH.lock().clone().unwrap_or_else(|| String::from("/"));
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: image/*,*/*\r\nConnection: close\r\n\r\n",
        path, host);
    if IMG_IS_HTTPS.load(Ordering::Relaxed) {
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
        let encrypted = match tls.encrypt_app(request.as_bytes()) {
            Ok(data) => data,
            Err(_) => {
                drop(tls_guard);
                img_cleanup();
                skip_current_image();
                return;
            }
        };
        drop(tls_guard);
        let wrapped = wrap_tls_record(0x17, &encrypted);
        if let Err(e) = tcp_send(&wrapped) {
            crate::sys::serial::print(b"[IMG-FETCH] send failed: ");
            crate::sys::serial::println(e.as_bytes());
            img_cleanup();
            skip_current_image();
            return;
        }
    } else {
        if let Err(e) = tcp_send(request.as_bytes()) {
            crate::sys::serial::print(b"[IMG-FETCH] send failed: ");
            crate::sys::serial::println(e.as_bytes());
            img_cleanup();
            skip_current_image();
            return;
        }
    }
    crate::sys::serial::println(b"[IMG-FETCH] request sent");
    crate::network::poll_network();
    IMG_DEADLINE.store(crate::time::timestamp_millis() + IMG_TIMEOUT_MS, Ordering::Relaxed);
    set_img_state(ImgFetchState::Receiving);
}
