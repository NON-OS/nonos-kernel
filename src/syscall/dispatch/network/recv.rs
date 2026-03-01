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
use super::types::SocketType;
use super::state::SOCKET_TABLE;

pub fn handle_recvfrom(sockfd: u64, buf: u64, len: u64, _flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if buf == 0 || len == 0 {
        return errno(22);
    }

    // SAFETY: Caller guarantees buf points to valid writable memory of at least len bytes.
    let buffer = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, len as usize)
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

        match stack.tcp_receive(conn_id, len as usize) {
            Ok(data) => {
                let recv_len = data.len().min(buffer.len());
                buffer[..recv_len].copy_from_slice(&data[..recv_len]);
                SyscallResult { value: recv_len as i64, capability_consumed: false, audit_required: false }
            }
            Err(_) => errno(11),
        }
    } else {
        let udp_id = match entry.udp_socket_id {
            Some(id) => id,
            None => return errno(9),
        };

        match crate::network::udp::recv(udp_id, buffer) {
            Ok(recv_len) => SyscallResult { value: recv_len as i64, capability_consumed: false, audit_required: false },
            Err(_) => errno(11),
        }
    }
}

pub fn handle_recvmsg(sockfd: u64, msg: u64, flags: u64) -> SyscallResult {
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

    handle_recvfrom(sockfd, buf, len, flags)
}

pub fn handle_recvmmsg(sockfd: u64, msgvec: u64, vlen: u64, flags: u64, timeout: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if msgvec == 0 || vlen == 0 {
        return errno(22);
    }

    let vlen = vlen.min(1024) as usize;

    let timeout_ms: Option<u64> = if timeout != 0 {
        // SAFETY: Caller guarantees timeout points to valid timespec structure.
        let timespec = unsafe { core::slice::from_raw_parts(timeout as *const i64, 2) };
        let tv_sec = timespec[0] as u64;
        let tv_nsec = timespec[1] as u64;
        Some(tv_sec * 1000 + tv_nsec / 1_000_000)
    } else {
        None
    };

    let start_time = crate::time::timestamp_millis();

    let mut recv_count = 0u64;

    for i in 0..vlen {
        if let Some(timeout_ms) = timeout_ms {
            let elapsed = crate::time::timestamp_millis() - start_time;
            if elapsed >= timeout_ms {
                break;
            }
        }

        let mmsghdr_ptr = msgvec + (i * MMSGHDR_SIZE) as u64;

        let msg_flags = if recv_count > 0 && (flags & 0x40) == 0 {
            flags | 0x40
        } else {
            flags
        };

        let result = handle_recvmsg(sockfd, mmsghdr_ptr, msg_flags);

        if result.value < 0 {
            if result.value == -11 && recv_count > 0 {
                break;
            }
            if recv_count == 0 {
                return result;
            }
            break;
        }

        if result.value == 0 {
            break;
        }

        // SAFETY: Caller guarantees mmsghdr_ptr + 56 points to valid msg_len field.
        let msg_len_ptr = (mmsghdr_ptr + 56) as *mut u32;
        unsafe {
            *msg_len_ptr = result.value as u32;
        }

        recv_count += 1;
    }

    SyscallResult {
        value: recv_count as i64,
        capability_consumed: false,
        audit_required: false,
    }
}
