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
use super::state::*;

pub(super) fn start_http_connection(ip: [u8; 4], port: u16) {
    let host = match PENDING_HOST.lock().clone() {
        Some(h) => h,
        None => {
            finish_with_error("no host");
            return;
        }
    };

    let path = PENDING_PATH.lock().clone().unwrap_or_else(|| String::from("/"));

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: NONOS/1.0\r\nAccept: text/html,*/*\r\nConnection: close\r\n\r\n",
        path, host
    );

    match http_start_request(ip, port, request.into_bytes()) {
        Ok(()) => {
            set_state(NavState::Connecting);
        }
        Err(e) => {
            finish_with_error(e);
        }
    }
}

pub(super) fn poll_http_connection() {
    match http_poll() {
        AsyncResult::Ready(data) => {
            *RESPONSE_DATA.lock() = data;
            set_state(NavState::ProcessingResponse);
        }
        AsyncResult::Pending => {}
        AsyncResult::Error(e) => {
            finish_with_error(e);
        }
    }
}
