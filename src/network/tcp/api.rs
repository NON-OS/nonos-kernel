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

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    ConnectionFailed,
    Timeout,
    Closed,
    SendFailed,
    RecvFailed,
    InvalidSocket,
}

pub fn connect_to(host: &str, port: u16, _timeout_ms: u32) -> Result<u32, TcpError> {
    use crate::network::stack::{get_network_stack, TcpSocket};
    use crate::network::dns;

    let addr = dns::resolve_v4(host).map_err(|_| TcpError::ConnectionFailed)?;

    let stack = get_network_stack().ok_or(TcpError::ConnectionFailed)?;
    let socket = TcpSocket::new();
    let conn_id = socket.connection_id();

    stack.tcp_connect(&socket, addr, port)
        .map_err(|_| TcpError::ConnectionFailed)?;

    Ok(conn_id)
}

pub fn send_socket(handle: u32, data: &[u8]) -> Result<(), TcpError> {
    use crate::network::stack::get_network_stack;

    let stack = get_network_stack().ok_or(TcpError::SendFailed)?;
    stack.tcp_send(handle, data)
        .map(|_| ())
        .map_err(|_| TcpError::SendFailed)
}

pub fn recv_socket(handle: u32, buffer: &mut [u8], _timeout_ms: u32) -> Result<usize, TcpError> {
    use crate::network::stack::get_network_stack;

    let stack = get_network_stack().ok_or(TcpError::RecvFailed)?;
    let data = stack.tcp_receive(handle, buffer.len())
        .map_err(|_| TcpError::RecvFailed)?;
    let len = data.len().min(buffer.len());
    buffer[..len].copy_from_slice(&data[..len]);
    Ok(len)
}

pub fn recv_socket_available(handle: u32, buffer: &mut [u8], _timeout_ms: u32) -> Result<usize, TcpError> {
    recv_socket(handle, buffer, 0)
}

pub fn close_socket(handle: u32) {
    use crate::network::stack::get_network_stack;

    if let Some(stack) = get_network_stack() {
        let _ = stack.tcp_close(handle);
    }
}

pub fn recv_all(handle: u32, timeout_ms: u32) -> Result<Vec<u8>, TcpError> {
    let mut result = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        match recv_socket(handle, &mut buffer, timeout_ms) {
            Ok(0) => break,
            Ok(n) => result.extend_from_slice(&buffer[..n]),
            Err(TcpError::Timeout) => break,
            Err(e) => return Err(e),
        }
    }

    Ok(result)
}
