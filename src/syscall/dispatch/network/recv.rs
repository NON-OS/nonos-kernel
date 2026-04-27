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

use super::super::{errno, require_capability};
use super::constants::MMSGHDR_SIZE;
use super::state::SOCKET_TABLE;
use super::types::SocketType;
use crate::capabilities::Capability;
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user, read_user_value, write_user_value};

pub fn handle_recvfrom(sockfd: u64, buf: u64, len: u64, _flags: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }
    if buf == 0 || len == 0 {
        return errno(22);
    }
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
                let recv_len = data.len().min(len as usize);
                if copy_to_user(buf, &data[..recv_len]).is_err() {
                    return errno(14);
                }
                SyscallResult {
                    value: recv_len as i64,
                    capability_consumed: false,
                    audit_required: false,
                }
            }
            Err(_) => errno(11),
        }
    } else {
        let udp_id = match entry.udp_socket_id {
            Some(id) => id,
            None => return errno(9),
        };
        let mut buffer = alloc::vec![0u8; len as usize];
        match crate::network::udp::recv(udp_id, &mut buffer) {
            Ok(recv_len) => {
                if copy_to_user(buf, &buffer[..recv_len]).is_err() {
                    return errno(14);
                }
                SyscallResult {
                    value: recv_len as i64,
                    capability_consumed: false,
                    audit_required: false,
                }
            }
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
    let mut msghdr_bytes = [0u8; 56];
    if copy_from_user(msg, &mut msghdr_bytes).is_err() {
        return errno(14);
    }
    // SAFETY: These slices are exactly 8 bytes from a 56-byte buffer, conversion cannot fail
    let iov_ptr = u64::from_ne_bytes(match msghdr_bytes[16..24].try_into() {
        Ok(arr) => arr,
        Err(_) => return errno(22), // EINVAL - should never happen with fixed buffer
    });
    let iovlen = u64::from_ne_bytes(match msghdr_bytes[24..32].try_into() {
        Ok(arr) => arr,
        Err(_) => return errno(22),
    });
    if iov_ptr == 0 || iovlen == 0 {
        return errno(22);
    }
    let mut iov_bytes = [0u8; 16];
    if copy_from_user(iov_ptr, &mut iov_bytes).is_err() {
        return errno(14);
    }
    // SAFETY: These slices are exactly 8 bytes from a 16-byte buffer
    let iov_base = u64::from_ne_bytes(match iov_bytes[0..8].try_into() {
        Ok(arr) => arr,
        Err(_) => return errno(22),
    });
    let iov_len = u64::from_ne_bytes(match iov_bytes[8..16].try_into() {
        Ok(arr) => arr,
        Err(_) => return errno(22),
    });
    handle_recvfrom(sockfd, iov_base, iov_len, flags)
}

pub fn handle_recvmmsg(
    sockfd: u64,
    msgvec: u64,
    vlen: u64,
    flags: u64,
    timeout: u64,
) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }
    if msgvec == 0 || vlen == 0 {
        return errno(22);
    }
    let vlen = vlen.min(1024) as usize;
    let timeout_ms: Option<u64> = if timeout != 0 {
        let tv_sec: i64 = match read_user_value(timeout) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let timeout_nsec = match timeout.checked_add(8) {
            Some(v) => v,
            None => return errno(14),
        };
        let tv_nsec: i64 = match read_user_value(timeout_nsec) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        let sec_ms = (tv_sec as u64).saturating_mul(1000);
        Some(sec_ms.saturating_add((tv_nsec as u64) / 1_000_000))
    } else {
        None
    };
    let start_time = crate::time::timestamp_millis();
    let mut recv_count = 0u64;
    for i in 0..vlen {
        if let Some(timeout_ms) = timeout_ms {
            if crate::time::timestamp_millis().saturating_sub(start_time) >= timeout_ms {
                break;
            }
        }
        let mmsghdr_offset = match (i as u64).checked_mul(MMSGHDR_SIZE as u64) {
            Some(v) => v,
            None => break,
        };
        let mmsghdr_ptr = match msgvec.checked_add(mmsghdr_offset) {
            Some(v) => v,
            None => break,
        };
        let msg_flags = if recv_count > 0 && (flags & 0x40) == 0 { flags | 0x40 } else { flags };
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
        let msg_len = result.value as u32;
        if write_user_value(mmsghdr_ptr + 56, &msg_len).is_err() {
            break;
        }
        recv_count += 1;
    }
    SyscallResult { value: recv_count as i64, capability_consumed: false, audit_required: false }
}
