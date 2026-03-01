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
use super::constants::MMSGHDR_SIZE;
use super::types::{SocketType, SocketState};
use super::state::SOCKET_TABLE;

pub fn handle_sendto(sockfd: u64, buf: u64, len: u64, _flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if buf == 0 || len == 0 || len > 65535 {
        return errno(22);
    }

    // SAFETY: Caller guarantees buf points to valid memory of at least len bytes.
    let data = unsafe {
        core::slice::from_raw_parts(buf as *const u8, len as usize)
    };

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };
    drop(table);

    if entry.socket_type == SocketType::Tcp {
        let conn_id = match entry.tcp_conn_id {
            Some(id) => id,
            None => return errno(107),
        };

        let stack = match crate::network::get_network_stack() {
            Some(s) => s,
            None => return errno(99),
        };

        match stack.tcp_send(conn_id, data) {
            Ok(sent) => SyscallResult { value: sent as i64, capability_consumed: false, audit_required: false },
            Err(_) => errno(32),
        }
    } else {
        let udp_id = match entry.udp_socket_id {
            Some(id) => id,
            None => return errno(9),
        };

        if entry.state == SocketState::Connected {
            match crate::network::udp::send(udp_id, data) {
                Ok(sent) => SyscallResult { value: sent as i64, capability_consumed: false, audit_required: false },
                Err(_) => errno(5),
            }
        } else if let Some(addr) = entry.remote_addr {
            match crate::network::udp::send_to(udp_id, data, addr, entry.remote_port) {
                Ok(sent) => SyscallResult { value: sent as i64, capability_consumed: false, audit_required: false },
                Err(_) => errno(5),
            }
        } else {
            errno(89)
        }
    }
}

pub fn handle_sendmsg(sockfd: u64, msg: u64, flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if msg == 0 {
        return errno(22);
    }

    // SAFETY: Caller guarantees msg points to valid msghdr structure.
    let msghdr = unsafe { core::slice::from_raw_parts(msg as *const u64, 7) };
    let iov_ptr = msghdr[2];
    let iovlen = msghdr[3];

    if iov_ptr == 0 || iovlen == 0 {
        return errno(22);
    }

    // SAFETY: Caller guarantees iov_ptr points to valid iovec structure.
    let iov = unsafe { core::slice::from_raw_parts(iov_ptr as *const u64, 2) };
    let buf = iov[0];
    let len = iov[1];

    handle_sendto(sockfd, buf, len, flags)
}

pub fn handle_sendmmsg(sockfd: u64, msgvec: u64, vlen: u64, flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if msgvec == 0 || vlen == 0 {
        return errno(22);
    }

    let vlen = vlen.min(1024) as usize;

    let mut sent_count = 0u64;

    for i in 0..vlen {
        let mmsghdr_ptr = msgvec + (i * MMSGHDR_SIZE) as u64;

        let result = handle_sendmsg(sockfd, mmsghdr_ptr, flags);

        if result.value < 0 {
            if sent_count == 0 {
                return result;
            }
            break;
        }

        // SAFETY: Caller guarantees mmsghdr_ptr + 56 points to valid msg_len field.
        let msg_len_ptr = (mmsghdr_ptr + 56) as *mut u32;
        unsafe {
            *msg_len_ptr = result.value as u32;
        }

        sent_count += 1;
    }

    SyscallResult {
        value: sent_count as i64,
        capability_consumed: false,
        audit_required: false,
    }
}
