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

use super::header::header;
use crate::security::keyring_capsule::protocol::types::{
    OP_DELETE, OP_LOCK, OP_METADATA, OP_RETRIEVE, OP_UNLOCK,
};

fn encode_pid_id(seq: u32, op: u16, caller_pid: u32, id: u32) -> Vec<u8> {
    let mut out = header(seq, op);
    out.extend_from_slice(&caller_pid.to_le_bytes());
    out.extend_from_slice(&id.to_le_bytes());
    out
}

pub(crate) fn encode_retrieve(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_RETRIEVE, caller_pid, id)
}

pub(crate) fn encode_delete(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_DELETE, caller_pid, id)
}

pub(crate) fn encode_lock(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_LOCK, caller_pid, id)
}

pub(crate) fn encode_unlock(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_UNLOCK, caller_pid, id)
}

pub(crate) fn encode_metadata(seq: u32, caller_pid: u32, id: u32) -> Vec<u8> {
    encode_pid_id(seq, OP_METADATA, caller_pid, id)
}
