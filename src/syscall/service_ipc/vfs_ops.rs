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

use super::protocol::{encode_open_request, encode_read_request, encode_write_request};
use super::protocol::{encode_close_request, encode_stat_request};
use super::fd_table::{allocate_fd, lookup_fd, close_fd};
use crate::services::ServiceClient;

const E_NOENT: i64 = -2;
const E_BADF: i64 = -9;
const E_NOMEM: i64 = -12;
const E_FAULT: i64 = -14;

pub fn ipc_open(pid: u32, path: &str, flags: i32, mode: u32) -> i64 {
    let client = match ServiceClient::connect("vfs") {
        Ok(c) => c, Err(_) => return E_NOENT,
    };
    let req = encode_open_request(path, flags, mode);
    let resp = match client.call(crate::services::protocol::ServiceOp::Open, req) {
        Ok(r) => r, Err(_) => return E_NOENT,
    };
    if resp.status != 0 { return resp.status as i64; }
    let handle = u64::from_le_bytes(resp.payload[0..8].try_into().unwrap_or([0; 8]));
    allocate_fd(pid, handle, flags) as i64
}

pub fn ipc_read(pid: u32, fd: i32, buf: *mut u8, count: usize) -> i64 {
    let handle = match lookup_fd(pid, fd) { Some(h) => h, None => return E_BADF };
    let addr = buf as u64;
    if crate::usercopy::validate_user_write(addr, count).is_err() { return E_FAULT; }
    let client = match ServiceClient::connect("vfs") {
        Ok(c) => c, Err(_) => return E_NOMEM,
    };
    let req = encode_read_request(handle, count);
    let resp = match client.call(crate::services::protocol::ServiceOp::Read, req) {
        Ok(r) => r, Err(_) => return E_NOMEM,
    };
    if resp.status != 0 { return resp.status as i64; }
    let read_len = resp.payload.len().min(count);
    if crate::usercopy::copy_to_user(addr, &resp.payload[..read_len]).is_err() { return E_FAULT; }
    read_len as i64
}

pub fn ipc_write(pid: u32, fd: i32, buf: *const u8, count: usize) -> i64 {
    let handle = match lookup_fd(pid, fd) { Some(h) => h, None => return E_BADF };
    let addr = buf as u64;
    if crate::usercopy::validate_user_read(addr, count).is_err() { return E_FAULT; }
    let mut data = alloc::vec![0u8; count];
    if crate::usercopy::copy_from_user(addr, &mut data).is_err() { return E_FAULT; }
    let client = match ServiceClient::connect("vfs") {
        Ok(c) => c, Err(_) => return E_NOMEM,
    };
    let req = encode_write_request(handle, &data);
    let resp = match client.call(crate::services::protocol::ServiceOp::Write, req) {
        Ok(r) => r, Err(_) => return E_NOMEM,
    };
    if resp.status != 0 { return resp.status as i64; }
    count as i64
}

pub fn ipc_close(pid: u32, fd: i32) -> i64 {
    let handle = match lookup_fd(pid, fd) { Some(h) => h, None => return E_BADF };
    let client = match ServiceClient::connect("vfs") { Ok(c) => c, Err(_) => return 0 };
    let req = encode_close_request(handle);
    let _ = client.call(crate::services::protocol::ServiceOp::Close, req);
    close_fd(pid, fd);
    0
}

pub fn ipc_stat(path: &str, statbuf: *mut u8) -> i64 {
    let addr = statbuf as u64;
    if crate::usercopy::validate_user_write(addr, 144).is_err() { return E_FAULT; }
    let client = match ServiceClient::connect("vfs") { Ok(c) => c, Err(_) => return E_NOENT };
    let req = encode_stat_request(path);
    let resp = match client.call(crate::services::protocol::ServiceOp::Query, req) {
        Ok(r) => r, Err(_) => return E_NOENT,
    };
    if resp.status != 0 { return resp.status as i64; }
    let copy_len = resp.payload.len().min(144);
    if crate::usercopy::copy_to_user(addr, &resp.payload[..copy_len]).is_err() { return E_FAULT; }
    0
}
