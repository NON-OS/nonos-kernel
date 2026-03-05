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

//! SOCKS5 Proxy Implementation
//!
//! Provides both SOCKS5 client and server functionality.
//! Server routes traffic through the onion network (port 9050, Anyone.io compatible).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

mod server;
mod protocol;

// Server functions re-exported for internal use
pub(crate) use server::{start_socks_server, stop_socks_server};

/// SOCKS client error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksError {
    ConnectionFailed,
    AuthFailed,
    TargetUnreachable,
    Timeout,
    ProtocolError,
    SendFailed,
    RecvFailed,
}

/// SOCKS client connection handle
pub struct SocksConnection {
    socket_handle: u32,
    connected: bool,
}

/// Connect to a SOCKS5 proxy server.
pub fn connect(host: &str, port: u16, timeout_ms: u32) -> Result<SocksConnection, SocksError> {
    use crate::network::tcp;

    let socket = tcp::connect_to(host, port, timeout_ms)
        .map_err(|_| SocksError::ConnectionFailed)?;

    // Perform SOCKS5 handshake (no auth)
    let handshake = [0x05, 0x01, 0x00]; // SOCKS5, 1 method, NO AUTH
    tcp::send_socket(socket, &handshake)
        .map_err(|_| SocksError::SendFailed)?;

    let mut response = [0u8; 2];
    tcp::recv_socket(socket, &mut response, timeout_ms)
        .map_err(|_| SocksError::RecvFailed)?;

    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(SocksError::AuthFailed);
    }

    Ok(SocksConnection {
        socket_handle: socket,
        connected: true,
    })
}

/// Connect to a target through the SOCKS5 proxy.
pub fn connect_target(
    conn: &SocksConnection,
    host: &str,
    port: u16,
    timeout_ms: u32,
) -> Result<(), SocksError> {
    use crate::network::tcp;

    // Build CONNECT request
    // [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    let mut request = Vec::with_capacity(7 + host.len());
    request.push(0x05); // VER
    request.push(0x01); // CMD: CONNECT
    request.push(0x00); // RSV
    request.push(0x03); // ATYP: DOMAINNAME
    request.push(host.len() as u8);
    request.extend_from_slice(host.as_bytes());
    request.push((port >> 8) as u8);
    request.push((port & 0xFF) as u8);

    tcp::send_socket(conn.socket_handle, &request)
        .map_err(|_| SocksError::SendFailed)?;

    // Read response
    let mut response = [0u8; 10];
    tcp::recv_socket(conn.socket_handle, &mut response, timeout_ms)
        .map_err(|_| SocksError::RecvFailed)?;

    if response[0] != 0x05 || response[1] != 0x00 {
        return Err(SocksError::TargetUnreachable);
    }

    Ok(())
}

/// Send data through SOCKS connection.
pub fn send(conn: &SocksConnection, data: &[u8]) -> Result<(), SocksError> {
    use crate::network::tcp;

    tcp::send_socket(conn.socket_handle, data)
        .map_err(|_| SocksError::SendFailed)
}

/// Receive data from SOCKS connection.
pub fn recv(conn: &SocksConnection, timeout_ms: u32) -> Result<Vec<u8>, SocksError> {
    use crate::network::tcp;

    let mut buffer = alloc::vec![0u8; 65536];
    let len = tcp::recv_socket_available(conn.socket_handle, &mut buffer, timeout_ms)
        .map_err(|_| SocksError::RecvFailed)?;

    buffer.truncate(len);
    Ok(buffer)
}

/// Close SOCKS connection.
pub fn close(conn: SocksConnection) {
    use crate::network::tcp;
    tcp::close_socket(conn.socket_handle);
}

pub fn format_connection_info(conn: &SocksConnection) -> String {
    alloc::format!("SOCKS5[handle={}, connected={}]", conn.socket_handle, conn.connected)
}

pub fn error_message(err: SocksError) -> String {
    match err {
        SocksError::ConnectionFailed => "Connection failed".into(),
        SocksError::AuthFailed => "Authentication failed".into(),
        SocksError::TargetUnreachable => "Target unreachable".into(),
        SocksError::Timeout => "Connection timed out".into(),
        SocksError::ProtocolError => "Protocol error".into(),
        SocksError::SendFailed => "Send failed".into(),
        SocksError::RecvFailed => "Receive failed".into(),
    }
}
