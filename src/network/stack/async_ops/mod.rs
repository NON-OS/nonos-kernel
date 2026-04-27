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
mod http;
mod ping;
mod tcp;

pub use dns::{dns_cancel, dns_poll, dns_start_query};
pub use http::{http_cancel, http_is_active, http_poll, http_start_request, HttpState};
pub use ping::{ping_cancel, ping_is_active, ping_poll, ping_start};
pub use tcp::{
    tcp_close, tcp_is_open, tcp_poll_connect, tcp_poll_receive, tcp_send, tcp_start_connect,
};

#[derive(Clone, Debug)]
pub enum AsyncResult<T> {
    Pending,
    Ready(T),
    Error(&'static str),
}
