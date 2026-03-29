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

use alloc::vec::Vec;

pub(super) const VFS_OP_OPEN: u8 = 0x01;
pub(super) const VFS_OP_READ: u8 = 0x02;
pub(super) const VFS_OP_WRITE: u8 = 0x03;
pub(super) const VFS_OP_CLOSE: u8 = 0x04;
pub(super) const VFS_OP_STAT: u8 = 0x05;

pub(super) fn encode_open_request(path: &str, flags: i32, mode: u32) -> Vec<u8> {
    let path_len = path.len() as u32;
    let mut buf = Vec::with_capacity(1 + 4 + 4 + 4 + path.len());
    buf.push(VFS_OP_OPEN);
    buf.extend_from_slice(&path_len.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf.extend_from_slice(&mode.to_le_bytes());
    buf.extend_from_slice(path.as_bytes());
    buf
}

pub(super) fn encode_read_request(handle: u64, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 8);
    buf.push(VFS_OP_READ);
    buf.extend_from_slice(&handle.to_le_bytes());
    buf.extend_from_slice(&(len as u64).to_le_bytes());
    buf
}

pub(super) fn encode_write_request(handle: u64, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 8 + data.len());
    buf.push(VFS_OP_WRITE);
    buf.extend_from_slice(&handle.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

pub(super) fn encode_close_request(handle: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8);
    buf.push(VFS_OP_CLOSE);
    buf.extend_from_slice(&handle.to_le_bytes());
    buf
}

pub(super) fn encode_stat_request(path: &str) -> Vec<u8> {
    let path_len = path.len() as u32;
    let mut buf = Vec::with_capacity(1 + 4 + path.len());
    buf.push(VFS_OP_STAT);
    buf.extend_from_slice(&path_len.to_le_bytes());
    buf.extend_from_slice(path.as_bytes());
    buf
}
