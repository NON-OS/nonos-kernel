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
use super::types::{SocketType, SocketState, SocketEntry};
use super::state::{NEXT_SOCKET_FD, SOCKET_TABLE};

pub fn handle_listen(sockfd: u64, backlog: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    let mut table = SOCKET_TABLE.lock();
    let entry = match table.get_mut(&(sockfd as u32)) {
        Some(e) => e,
        None => return errno(9),
    };

    if entry.socket_type != SocketType::Tcp {
        return errno(95);
    }

    if entry.state != SocketState::Bound {
        return errno(22);
    }

    if let Some(stack) = crate::network::get_network_stack() {
        if stack.listen_tcp(backlog as usize).is_err() {
            return errno(5);
        }
    }

    entry.state = SocketState::Listening;

    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}

pub fn handle_accept(sockfd: u64, _addr: u64, _addrlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };
    drop(table);

    if entry.socket_type != SocketType::Tcp {
        return errno(95);
    }

    if entry.state != SocketState::Listening {
        return errno(22);
    }

    let stack = match crate::network::get_network_stack() {
        Some(s) => s,
        None => return errno(99),
    };

    match stack.accept_tcp_connection() {
        Ok(conn_id) => {
            let new_fd = NEXT_SOCKET_FD.fetch_add(1, AtomicOrdering::SeqCst);

            let new_entry = SocketEntry {
                socket_type: SocketType::Tcp,
                state: SocketState::Connected,
                local_port: entry.local_port,
                remote_addr: None,
                remote_port: 0,
                tcp_conn_id: Some(conn_id),
                udp_socket_id: None,
            };

            SOCKET_TABLE.lock().insert(new_fd, new_entry);

            SyscallResult { value: new_fd as i64, capability_consumed: false, audit_required: true }
        }
        Err(_) => errno(11),
    }
}

pub fn handle_accept4(sockfd: u64, addr: u64, addrlen: u64, _flags: i32) -> SyscallResult {
    handle_accept(sockfd, addr, addrlen)
}
