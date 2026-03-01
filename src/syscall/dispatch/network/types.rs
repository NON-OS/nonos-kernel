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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Created,
    Bound,
    Listening,
    Connected,
    Closed,
}

#[derive(Clone)]
pub struct SocketEntry {
    pub socket_type: SocketType,
    pub state: SocketState,
    pub local_port: u16,
    pub remote_addr: Option<[u8; 4]>,
    pub remote_port: u16,
    pub tcp_conn_id: Option<u32>,
    pub udp_socket_id: Option<u32>,
}
