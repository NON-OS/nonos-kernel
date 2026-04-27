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

mod bind;
mod connect;
mod constants;
mod info;
mod listen;
mod options;
mod recv;
mod send;
mod socket;
mod state;
mod types;

pub use bind::handle_bind;
pub use connect::handle_connect;
pub use info::{handle_getpeername, handle_getsockname, handle_shutdown};
pub use listen::{handle_accept, handle_accept4, handle_listen};
pub use options::{handle_getsockopt, handle_setsockopt};
pub use recv::{handle_recvfrom, handle_recvmmsg, handle_recvmsg};
pub use send::{handle_sendmmsg, handle_sendmsg, handle_sendto};
pub use socket::{handle_socket, handle_socketpair};
pub use state::SOCKET_TABLE;
pub use types::{SocketEntry, SocketState, SocketType};
