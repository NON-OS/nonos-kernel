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

mod config;
mod connect;
mod lifecycle;
mod listener;
mod receive;
mod send;

pub use config::{
    get_config, set_buffer_sizes, set_timeouts, TcpConfig, TcpTimeouts, DEFAULT_TCP_CONFIG,
};
pub use connect::{connect_v4, connect_v6};
pub use lifecycle::{
    abort, cleanup_stale_connections, close, get_active_connection_count, get_connection_state,
    is_connection_active,
};
pub use listener::{accept, bind, get_pending_connection_count, unbind};
pub use receive::{peek, receive, receive_exact, receive_with_timeout, try_receive};
pub use send::send;
