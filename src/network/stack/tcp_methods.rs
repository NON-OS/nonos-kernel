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

use alloc::vec::Vec;

use super::core::NetworkStack;
use super::tcp;
use super::types::{Socket, TcpSocket};
use crate::network::ip::IpAddress;

impl NetworkStack {
    pub fn bind_tcp_port(&self, port: u16) -> Result<(), &'static str> {
        tcp::bind(self, port, 16)
    }

    pub fn listen_tcp(&self, port: u16, backlog: usize) -> Result<(), &'static str> {
        tcp::bind(self, port, backlog)
    }

    pub fn accept_tcp_connection(&self, port: u16) -> Result<u32, &'static str> {
        tcp::accept(self, port)
    }

    pub fn connect_tcp(&self, addr: IpAddress, port: u16) -> Result<u32, &'static str> {
        match addr {
            IpAddress::V4(a) => tcp::connect_v4(self, a, port),
            IpAddress::V6(a) => tcp::connect_v6(self, a, port),
        }
    }

    pub fn tcp_connect(&self, _sock: &TcpSocket, addr_v4: [u8; 4], port: u16) -> Result<(), &'static str> {
        tcp::connect_v4(self, addr_v4, port).map(|_| ())
    }

    pub fn tcp_connect_v6(&self, _sock: &TcpSocket, addr_v6: [u8; 16], port: u16) -> Result<(), &'static str> {
        tcp::connect_v6(self, addr_v6, port).map(|_| ())
    }

    pub fn tcp_connect_ip(&self, sock: &TcpSocket, addr: IpAddress, port: u16) -> Result<(), &'static str> {
        match addr {
            IpAddress::V4(v4) => self.tcp_connect(sock, v4, port),
            IpAddress::V6(v6) => self.tcp_connect_v6(sock, v6, port),
        }
    }

    pub fn tcp_send(&self, conn_id: u32, buf: &[u8]) -> Result<usize, &'static str> {
        tcp::send(self, conn_id, buf)
    }

    pub fn tcp_receive(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        tcp::receive(self, conn_id, max_len)
    }

    pub fn tcp_close(&self, conn_id: u32) -> Result<(), &'static str> {
        tcp::close(self, conn_id)
    }

    pub fn tcp_abort(&self, conn_id: u32) -> Result<(), &'static str> {
        tcp::abort(self, conn_id)
    }

    pub fn tcp_is_closed(&self, conn_id: u32) -> Option<bool> {
        Some(!tcp::is_connection_active(self, conn_id))
    }

    pub fn get_local_port(&self, _sock: &TcpSocket) -> Option<u16> {
        None
    }

    pub fn send_tcp_data(&self, socket: &Socket, data: &[u8]) -> Result<usize, &'static str> {
        let id = socket.connection_id()
            .or_else(|| self.pick_single_active_conn())
            .ok_or("no connection")?;
        self.tcp_send(id, data)
    }

    pub fn recv_tcp_data(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, &'static str> {
        self.tcp_receive(conn_id, max_len)
    }

    pub fn send_tcp_packet(&self, data: &[u8]) -> Result<(), &'static str> {
        let id = self.pick_single_active_conn().ok_or("no active connection")?;
        self.tcp_send(id, data).map(|_| ())
    }
}
