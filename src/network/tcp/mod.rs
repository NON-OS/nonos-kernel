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

mod api;
mod types;
mod socket;

pub use api::{TcpError, connect_to, send_socket, recv_socket, recv_socket_available, close_socket, recv_all};
pub use types::{TcpState, TcpHeader, TcpConnection, TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST, TCP_PSH};
pub use socket::TcpSocket;
