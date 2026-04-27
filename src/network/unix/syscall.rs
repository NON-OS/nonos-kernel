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

use super::address::parse_unix_address;
use super::socket::{UnixSocket, UnixSocketType};
use alloc::sync::Arc;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_SEQPACKET: u32 = 5;
pub const SOCK_NONBLOCK: u32 = 0x800;
pub const SOCK_CLOEXEC: u32 = 0x80000;

pub fn unix_socket(socket_type: u32, flags: u32) -> Result<i32, i32> {
    let typ = match socket_type & 0xf {
        SOCK_STREAM => UnixSocketType::Stream,
        SOCK_DGRAM => UnixSocketType::Dgram,
        SOCK_SEQPACKET => UnixSocketType::Seqpacket,
        _ => return Err(-22),
    };
    let socket = Arc::new(UnixSocket::new(typ, flags));
    let fd = crate::fs::allocate_fd()?;
    crate::fs::register_unix_socket(fd, socket);
    if (socket_type & SOCK_CLOEXEC) != 0 {
        crate::fs::set_cloexec(fd, true);
    }
    Ok(fd)
}

pub fn unix_bind(fd: i32, addr_ptr: u64, addr_len: usize) -> Result<i32, i32> {
    let socket = crate::fs::get_unix_socket(fd).ok_or(-9)?;
    let addr = parse_unix_address(addr_ptr, addr_len)?;
    super::listen::bind_unix(&socket, &addr.path())?;
    Ok(0)
}

pub fn unix_listen(fd: i32, backlog: i32) -> Result<i32, i32> {
    let socket = crate::fs::get_unix_socket(fd).ok_or(-9)?;
    super::listen::listen_unix(&socket, backlog)?;
    Ok(0)
}

pub fn unix_accept(fd: i32, addr_ptr: u64, addr_len_ptr: u64) -> Result<i32, i32> {
    let socket = crate::fs::get_unix_socket(fd).ok_or(-9)?;
    let peer = socket.backlog.lock().pop_front().ok_or(-11)?;
    let new_fd = crate::fs::allocate_fd()?;
    crate::fs::register_unix_socket(new_fd, peer.clone());
    if addr_ptr != 0 && addr_len_ptr != 0 {
        if let Some(path) = peer.bound_path.lock().as_ref() {
            let addr = super::address::format_unix_address(path);
            let len = super::address::address_len(&addr) as u32;
            let _ = crate::usercopy::write_user_value(addr_ptr, &addr);
            let _ = crate::usercopy::write_user_value(addr_len_ptr, &len);
        }
    }
    Ok(new_fd)
}

pub fn unix_connect(fd: i32, addr_ptr: u64, addr_len: usize) -> Result<i32, i32> {
    let socket = crate::fs::get_unix_socket(fd).ok_or(-9)?;
    let addr = parse_unix_address(addr_ptr, addr_len)?;
    let path = addr.path();
    match socket.socket_type {
        UnixSocketType::Stream => {
            super::stream::stream_connect(&socket, &path)?;
        }
        UnixSocketType::Seqpacket => {
            super::seqpacket::seqpacket_connect(&socket, &path)?;
        }
        UnixSocketType::Dgram => {
            let peer = super::listen::lookup_bound_socket(&path)?;
            socket.connect(peer)?;
        }
    }
    Ok(0)
}
