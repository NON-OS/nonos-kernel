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

const SOL_SOCKET: u64 = 1;
const SOL_TCP: u64 = 6;

const SO_REUSEADDR: u64 = 2;
const SO_BROADCAST: u64 = 6;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const TCP_NODELAY: u64 = 1;

pub fn handle_setsockopt(sockfd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    let mut table = SOCKET_TABLE.lock();
    let entry = match table.get_mut(&(sockfd as u32)) {
        Some(e) => e,
        None => return errno(9),
    };

    if optval == 0 || optlen < 4 {
        return errno(22);
    }

    let int_val: i32 = match read_user_value(optval) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };

    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => entry.options.reuseaddr = int_val != 0,
        (SOL_SOCKET, SO_REUSEPORT) => entry.options.reuseport = int_val != 0,
        (SOL_SOCKET, SO_KEEPALIVE) => entry.options.keepalive = int_val != 0,
        (SOL_SOCKET, SO_BROADCAST) => entry.options.broadcast = int_val != 0,
        (SOL_SOCKET, SO_SNDBUF) => entry.options.sndbuf = int_val.max(0) as u32,
        (SOL_SOCKET, SO_RCVBUF) => entry.options.rcvbuf = int_val.max(0) as u32,
        (SOL_SOCKET, SO_LINGER) => {
            if int_val != 0 && optlen >= 8 {
                let linger_val: i32 = read_user_value(optval + 4).unwrap_or(0);
                entry.options.linger = Some(linger_val.max(0) as u32);
            } else {
                entry.options.linger = None;
            }
        }
        (SOL_SOCKET, SO_RCVTIMEO) => {
            if optlen >= 16 {
                let sec: i64 = read_user_value(optval).unwrap_or(0);
                let usec: i64 = read_user_value(optval + 8).unwrap_or(0);
                entry.options.rcvtimeo_ms = (sec as u64).saturating_mul(1000).saturating_add((usec as u64) / 1000);
            }
        }
        (SOL_SOCKET, SO_SNDTIMEO) => {
            if optlen >= 16 {
                let sec: i64 = read_user_value(optval).unwrap_or(0);
                let usec: i64 = read_user_value(optval + 8).unwrap_or(0);
                entry.options.sndtimeo_ms = (sec as u64).saturating_mul(1000).saturating_add((usec as u64) / 1000);
            }
        }
        (SOL_TCP, TCP_NODELAY) => entry.options.nodelay = int_val != 0,
        _ => {}
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

const SO_ERROR: u64 = 4;
const SO_TYPE: u64 = 3;

pub fn handle_getsockopt(sockfd: u64, level: u64, optname: u64, optval: u64, optlen_ptr: u64) -> SyscallResult {
    if let Err(e) = require_capability(Capability::Network) {
        return e;
    }

    if optval == 0 || optlen_ptr == 0 {
        return errno(22);
    }

    let table = SOCKET_TABLE.lock();
    let entry = match table.get(&(sockfd as u32)) {
        Some(e) => e.clone(),
        None => return errno(9),
    };

    let write_int = |val: i32| -> SyscallResult {
        if write_user_value(optval, &val).is_err() { return errno(14); }
        if write_user_value(optlen_ptr, &4u32).is_err() { return errno(14); }
        SyscallResult { value: 0, capability_consumed: false, audit_required: false }
    };

    match (level, optname) {
        (SOL_SOCKET, SO_ERROR) => write_int(0),
        (SOL_SOCKET, SO_TYPE) => {
            let type_val = if entry.socket_type == SocketType::Tcp { SOCK_STREAM as i32 } else { SOCK_DGRAM as i32 };
            write_int(type_val)
        }
        (SOL_SOCKET, SO_REUSEADDR) => write_int(if entry.options.reuseaddr { 1 } else { 0 }),
        (SOL_SOCKET, SO_REUSEPORT) => write_int(if entry.options.reuseport { 1 } else { 0 }),
        (SOL_SOCKET, SO_KEEPALIVE) => write_int(if entry.options.keepalive { 1 } else { 0 }),
        (SOL_SOCKET, SO_BROADCAST) => write_int(if entry.options.broadcast { 1 } else { 0 }),
        (SOL_SOCKET, SO_SNDBUF) => write_int(entry.options.sndbuf as i32),
        (SOL_SOCKET, SO_RCVBUF) => write_int(entry.options.rcvbuf as i32),
        (SOL_SOCKET, SO_LINGER) => {
            let onoff = if entry.options.linger.is_some() { 1i32 } else { 0i32 };
            let linger_val = entry.options.linger.unwrap_or(0) as i32;
            if write_user_value(optval, &onoff).is_err() { return errno(14); }
            if write_user_value(optval + 4, &linger_val).is_err() { return errno(14); }
            if write_user_value(optlen_ptr, &8u32).is_err() { return errno(14); }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        (SOL_SOCKET, SO_RCVTIMEO) => {
            let sec = (entry.options.rcvtimeo_ms / 1000) as i64;
            let usec = ((entry.options.rcvtimeo_ms % 1000) * 1000) as i64;
            if write_user_value(optval, &sec).is_err() { return errno(14); }
            if write_user_value(optval + 8, &usec).is_err() { return errno(14); }
            if write_user_value(optlen_ptr, &16u32).is_err() { return errno(14); }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        (SOL_SOCKET, SO_SNDTIMEO) => {
            let sec = (entry.options.sndtimeo_ms / 1000) as i64;
            let usec = ((entry.options.sndtimeo_ms % 1000) * 1000) as i64;
            if write_user_value(optval, &sec).is_err() { return errno(14); }
            if write_user_value(optval + 8, &usec).is_err() { return errno(14); }
            if write_user_value(optlen_ptr, &16u32).is_err() { return errno(14); }
            SyscallResult { value: 0, capability_consumed: false, audit_required: false }
        }
        (SOL_TCP, TCP_NODELAY) => write_int(if entry.options.nodelay { 1 } else { 0 }),
        _ => write_int(0),
    }
}
