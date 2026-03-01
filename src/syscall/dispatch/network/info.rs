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

pub fn handle_shutdown(sockfd: i32, _how: i32) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };
    drop(table);

    if entry.socket_type == SocketType::Tcp {
        if let Some(conn_id) = entry.tcp_conn_id {
            if let Some(stack) = crate::network::get_network_stack() {
                let _ = stack.tcp_close(conn_id);
            }
        }
    }

    let mut table = SOCKET_TABLE.lock();
    if let Some(entry) = table.get_mut(&(sockfd as u32)) {
        entry.state = SocketState::Closed;
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_getsockname(sockfd: u64, addr: u64, addrlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if addr == 0 || addrlen == 0 {
        return errno(22);
    }

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };

    // SAFETY: Caller guarantees addr points to valid writable memory of at least 16 bytes.
    let sockaddr = unsafe {
        core::slice::from_raw_parts_mut(addr as *mut u8, 16)
    };
    sockaddr[0] = 2;
    sockaddr[1] = 0;
    sockaddr[2] = (entry.local_port >> 8) as u8;
    sockaddr[3] = (entry.local_port & 0xFF) as u8;
    sockaddr[4..8].fill(0);
    sockaddr[8..16].fill(0);

    // SAFETY: Caller guarantees addrlen points to valid writable u32.
    unsafe { core::ptr::write(addrlen as *mut u32, 16) };

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_getpeername(sockfd: u64, addr: u64, addrlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if addr == 0 || addrlen == 0 {
        return errno(22);
    }

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };

    if entry.state != SocketState::Connected {
        return errno(107);
    }

    let remote_addr = entry.remote_addr.unwrap_or([0, 0, 0, 0]);

    // SAFETY: Caller guarantees addr points to valid writable memory of at least 16 bytes.
    let sockaddr = unsafe {
        core::slice::from_raw_parts_mut(addr as *mut u8, 16)
    };
    sockaddr[0] = 2;
    sockaddr[1] = 0;
    sockaddr[2] = (entry.remote_port >> 8) as u8;
    sockaddr[3] = (entry.remote_port & 0xFF) as u8;
    sockaddr[4..8].copy_from_slice(&remote_addr);
    sockaddr[8..16].fill(0);

    // SAFETY: Caller guarantees addrlen points to valid writable u32.
    unsafe { core::ptr::write(addrlen as *mut u32, 16) };

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
