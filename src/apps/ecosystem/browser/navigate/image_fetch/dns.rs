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
use super::types::*;
use crate::network::stack::async_ops::{dns_cancel, dns_poll, tcp_start_connect, AsyncResult};
use core::sync::atomic::Ordering;

pub(super) fn poll_img_dns() {
    if is_timed_out() {
        crate::sys::serial::println(b"[IMG-FETCH] DNS timeout");
        dns_cancel();
        skip_current_image();
        return;
    }
    match dns_poll() {
        AsyncResult::Ready(ip) => {
            crate::sys::serial::print(b"[IMG-FETCH] resolved ");
            crate::sys::serial::print_dec(ip[0] as u64);
            crate::sys::serial::print(b".");
            crate::sys::serial::print_dec(ip[1] as u64);
            crate::sys::serial::print(b".");
            crate::sys::serial::print_dec(ip[2] as u64);
            crate::sys::serial::print(b".");
            crate::sys::serial::print_dec(ip[3] as u64);
            crate::sys::serial::println(b"");
            *IMG_IP.lock() = Some(ip);
            let port = *IMG_PORT.lock();
            match tcp_start_connect(ip, port) {
                Ok(conn_id) => {
                    IMG_CONN_ID.store(conn_id, Ordering::Relaxed);
                    set_img_state(ImgFetchState::Connecting);
                }
                Err(e) => {
                    crate::sys::serial::print(b"[IMG-FETCH] tcp start failed: ");
                    crate::sys::serial::println(e.as_bytes());
                    skip_current_image();
                }
            }
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            crate::sys::serial::print(b"[IMG-FETCH] DNS error: ");
            crate::sys::serial::println(e.as_bytes());
            skip_current_image();
        }
    }
}
