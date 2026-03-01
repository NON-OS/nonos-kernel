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

mod constants;
mod types;
mod state;
mod socket;
mod bind;
mod listen;
mod connect;
mod send;
mod recv;
mod info;
mod options;

pub use types::{SocketType, SocketState, SocketEntry};
pub use state::SOCKET_TABLE;
pub use socket::{handle_socket, handle_socketpair};
pub use bind::handle_bind;
pub use listen::{handle_listen, handle_accept, handle_accept4};
pub use connect::handle_connect;
pub use send::{handle_sendto, handle_sendmsg, handle_sendmmsg};
pub use recv::{handle_recvfrom, handle_recvmsg, handle_recvmmsg};
pub use info::{handle_shutdown, handle_getsockname, handle_getpeername};
pub use options::{handle_setsockopt, handle_getsockopt};
