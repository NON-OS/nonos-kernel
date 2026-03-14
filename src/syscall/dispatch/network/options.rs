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
use crate::usercopy::{copy_to_user, read_user_value, write_user_value};
use super::super::{errno, require_capability};
use super::constants::{SOCK_STREAM, SOCK_DGRAM};
use super::types::SocketType;
use super::state::SOCKET_TABLE;

pub fn handle_setsockopt(sockfd: u64, _level: u64, _optname: u64, _optval: u64, _optlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    let table = SOCKET_TABLE.lock();
    if !table.contains_key(&(sockfd as u32)) {
        return errno(9);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_getsockopt(sockfd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if optval == 0 || optlen == 0 {
        return errno(22);
    }

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };

    if level == 1 && optname == 4 {
        let zero: i32 = 0;
        if write_user_value(optval, &zero).is_err() {
            return errno(14);
        }
        let len: u32 = 4;
        if write_user_value(optlen, &len).is_err() {
            return errno(14);
        }
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    if level == 1 && optname == 3 {
        let type_val: u64 = if entry.socket_type == SocketType::Tcp { SOCK_STREAM } else { SOCK_DGRAM };
        if write_user_value(optval, &type_val).is_err() {
            return errno(14);
        }
        let len: u32 = 4;
        if write_user_value(optlen, &len).is_err() {
            return errno(14);
        }
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let len: u32 = match read_user_value(optlen) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    let buf_len = (len as usize).min(64);
    let zeros = [0u8; 64];

    if copy_to_user(optval, &zeros[..buf_len]).is_err() {
        return errno(14);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
