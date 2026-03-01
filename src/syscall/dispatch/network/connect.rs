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

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use super::super::{errno, require_capability};
use super::types::{SocketType, SocketState};
use super::state::SOCKET_TABLE;

pub fn handle_connect(sockfd: u64, addr: u64, addrlen: u64, _flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if addr == 0 || addrlen < 8 {
        return errno(22);
    }

    // SAFETY: Caller guarantees addr points to valid sockaddr_in structure of at least addrlen bytes.
    let sockaddr = unsafe {
        core::slice::from_raw_parts(addr as *const u8, addrlen as usize)
    };

    let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
    let ip = [sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7]];

    let mut table = SOCKET_TABLE.lock();
    let entry = match table.get_mut(&(sockfd as u32)) {
        Some(e) => e,
        None => return errno(9),
    };

    if entry.state == SocketState::Connected {
        return errno(106);
    }

    if entry.socket_type == SocketType::Tcp {
        drop(table);

        let stack = match crate::network::get_network_stack() {
            Some(s) => s,
            None => return errno(99),
        };

        let sock = crate::network::stack::TcpSocket::new();
        let conn_id = sock.connection_id();

        match stack.tcp_connect(&sock, ip, port) {
            Ok(()) => {
                let mut table = SOCKET_TABLE.lock();
                if let Some(entry) = table.get_mut(&(sockfd as u32)) {
                    entry.state = SocketState::Connected;
                    entry.remote_addr = Some(ip);
                    entry.remote_port = port;
                    entry.tcp_conn_id = Some(conn_id);
                }
                SyscallResult { value: 0, capability_consumed: false, audit_required: true }
            }
            Err(_) => errno(111),
        }
    } else {
        entry.remote_addr = Some(ip);
        entry.remote_port = port;
        entry.state = SocketState::Connected;

        if let Some(udp_id) = entry.udp_socket_id {
            let _ = crate::network::udp::connect(udp_id, ip, port);
        }

        SyscallResult { value: 0, capability_consumed: false, audit_required: true }
    }
}
