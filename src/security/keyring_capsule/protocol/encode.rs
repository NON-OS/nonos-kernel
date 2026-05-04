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

use alloc::vec::Vec;

use super::types::{
    HDR_LEN, OP_COUNT, OP_DELETE, OP_LOCK, OP_METADATA, OP_RETRIEVE, OP_STORE, OP_UNLOCK,
};

fn header(seq: u32, op: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR_LEN);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn encode_store(
    seq: u32,
    caller_pid: u32,
    now: u64,
    expires_at: u64,
    key_type: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut out = header(seq, OP_STORE);
    out.extend_from_slice(&caller_pid.to_le_bytes());
    out.extend_from_slice(&now.to_le_bytes());
    out.extend_from_slice(&expires_at.to_le_bytes());
    out.push(key_type);
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(data);
    out
}

pub fn encode_pid_id(seq: u32, op: u16, caller_pid: u32, id: u32) -> Vec<u8> {
    let mut out = header(seq, op);
    out.extend_from_slice(&caller_pid.to_le_bytes());
    out.extend_from_slice(&id.to_le_bytes());
    out
}

pub fn encode_retrieve(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_RETRIEVE, caller_pid, id)
}

pub fn encode_delete(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_DELETE, caller_pid, id)
}

pub fn encode_lock(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_LOCK, caller_pid, id)
}

pub fn encode_unlock(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_UNLOCK, caller_pid, id)
}

pub fn encode_metadata(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_METADATA, caller_pid, id)
}

pub fn encode_count(seq: u32, caller_pid: u32) -> Vec<u8> {
    let mut out = header(seq, OP_COUNT);
    out.extend_from_slice(&caller_pid.to_le_bytes());
    out
}
