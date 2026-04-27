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

use super::queue::skip_current_image;
use super::tls::start_img_tls;
use super::types::*;
use crate::network::stack::async_ops::{tcp_close, tcp_poll_connect, AsyncResult};
use core::sync::atomic::Ordering;

pub(super) fn img_cleanup() {
    tcp_close();
    IMG_CONN_ID.store(0, Ordering::Relaxed);
    *IMG_TLS.lock() = None;
    IMG_REASSEMBLY.lock().clear();
}

pub(super) fn poll_img_connect() {
    if is_timed_out() {
        crate::sys::serial::println(b"[IMG-FETCH] connect timeout");
        img_cleanup();
        skip_current_image();
        return;
    }
    match tcp_poll_connect() {
        AsyncResult::Ready(()) => {
            if IMG_IS_HTTPS.load(Ordering::Relaxed) {
                crate::sys::serial::println(b"[IMG-FETCH] connected, starting TLS");
                start_img_tls();
            } else {
                crate::sys::serial::println(b"[IMG-FETCH] connected (HTTP), sending");
                set_img_state(ImgFetchState::Sending);
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[IMG-FETCH] connect error: ");
            crate::sys::serial::println(e.as_bytes());
            skip_current_image();
        }
    }
}
