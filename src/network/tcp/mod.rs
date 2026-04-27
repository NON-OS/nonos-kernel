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
mod socket;
mod types;

pub use api::{
    close_socket, connect_to, recv_all, recv_socket, recv_socket_available, send_data, send_socket,
    TcpError,
};
pub use socket::TcpSocket;
pub use types::{TcpConnection, TcpHeader, TcpState, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
