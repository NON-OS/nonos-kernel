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

use core::sync::atomic::Ordering as AtomicOrdering;

use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use super::super::{errno, require_capability};
use super::constants::{AF_INET, AF_UNIX, SOCK_STREAM, SOCK_DGRAM};
use super::types::{SocketType, SocketState, SocketEntry};
use super::state::{NEXT_SOCKET_FD, SOCKET_TABLE};

pub fn handle_socket(domain: u64, socket_type: u64, _protocol: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if domain != AF_INET {
        return errno(97);
    }

    let sock_type = match socket_type {
        SOCK_STREAM => SocketType::Tcp,
        SOCK_DGRAM => SocketType::Udp,
        _ => return errno(94),
    };

    let fd = NEXT_SOCKET_FD.fetch_add(1, AtomicOrdering::SeqCst);

    let entry = SocketEntry {
        socket_type: sock_type,
        state: SocketState::Created,
        local_port: 0,
        remote_addr: None,
        remote_port: 0,
        tcp_conn_id: None,
        udp_socket_id: if sock_type == SocketType::Udp {
            match crate::network::udp::create_socket() {
                Ok(id) => Some(id),
                Err(_) => return errno(24),
            }
        } else {
            None
        },
    };

    SOCKET_TABLE.lock().insert(fd, entry);

    SyscallResult { value: fd as i64, capability_consumed: false, audit_required: true }
}

pub fn handle_socketpair(domain: u64, socket_type: u64, _protocol: u64, sv: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if sv == 0 {
        return errno(22);
    }

    if domain != AF_UNIX {
        return errno(97);
    }

    let fd1 = NEXT_SOCKET_FD.fetch_add(1, AtomicOrdering::SeqCst);
    let fd2 = NEXT_SOCKET_FD.fetch_add(1, AtomicOrdering::SeqCst);

    let entry1 = SocketEntry {
        socket_type: if socket_type == SOCK_STREAM { SocketType::Tcp } else { SocketType::Udp },
        state: SocketState::Connected,
        local_port: 0,
        remote_addr: None,
        remote_port: 0,
        tcp_conn_id: None,
        udp_socket_id: None,
    };

    let entry2 = entry1.clone();

    let mut table = SOCKET_TABLE.lock();
    table.insert(fd1, entry1);
    table.insert(fd2, entry2);

    // SAFETY: Caller guarantees sv points to valid memory for two i32 values.
    unsafe {
        core::ptr::write(sv as *mut i32, fd1 as i32);
        core::ptr::write((sv + 4) as *mut i32, fd2 as i32);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
