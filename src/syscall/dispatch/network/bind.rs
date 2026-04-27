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

use super::super::{errno, require_capability};
use super::state::SOCKET_TABLE;
use super::types::{SocketState, SocketType};
use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_from_user;

pub fn handle_bind(sockfd: u64, addr: u64, addrlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }
    if addr == 0 || addrlen < 8 {
        return errno(22);
    }
    let len = (addrlen as usize).min(128);
    let mut sockaddr = [0u8; 128];
    if copy_from_user(addr, &mut sockaddr[..len]).is_err() {
        return errno(14);
    }
    let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
    let mut table = SOCKET_TABLE.lock();
    let entry = match table.get_mut(&(sockfd as u32)) {
        Some(e) => e,
        None => return errno(9),
    };
    if entry.state != SocketState::Created {
        return errno(22);
    }
    entry.local_port = port;
    entry.state = SocketState::Bound;
    if entry.socket_type == SocketType::Tcp {
        if let Some(stack) = crate::network::get_network_stack() {
            if stack.bind_tcp_port(port).is_err() {
                return errno(98);
            }
        } else {
            return errno(99);
        }
    }
    if let Some(udp_id) = entry.udp_socket_id {
        if crate::network::udp::bind(udp_id, port).is_err() {
            return errno(98);
        }
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
