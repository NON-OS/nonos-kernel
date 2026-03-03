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

mod dns;
mod tcp;
mod http;
mod ping;

pub use dns::{dns_start_query, dns_poll, dns_cancel};
pub use tcp::{tcp_start_connect, tcp_poll_connect, tcp_send, tcp_poll_receive, tcp_is_open, tcp_close};
pub use http::{http_start_request, http_poll, http_cancel, http_is_active, HttpState};
pub use ping::{ping_start, ping_poll, ping_is_active, ping_cancel};

#[derive(Clone, Debug)]
pub enum AsyncResult<T> {
    Pending,
    Ready(T),
    Error(&'static str),
}
