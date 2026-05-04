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

// Kernel-side mirror of `userland/capsule_vfs/src/protocol/*`.

use alloc::vec::Vec;

pub(super) const MAGIC: u32 = 0x4E4F_5646; // "NOVF"
pub(super) const VERSION: u16 = 1;

pub(super) const OP_OPEN: u16 = 1;
pub(super) const OP_CLOSE: u16 = 2;
pub(super) const OP_READ: u16 = 3;
pub(super) const OP_WRITE: u16 = 4;
pub(super) const OP_STAT: u16 = 5;
pub(super) const OP_LIST: u16 = 6;

pub(super) const O_CREATE: u32 = 1 << 0;
pub(super) const O_TRUNC: u32 = 1 << 1;
pub(super) const O_APPEND: u32 = 1 << 2;

pub(super) const MAX_PATH_BYTES: u32 = 256;
pub(super) const MAX_DATA_BYTES: u32 = 65536;
pub(super) const MAX_PAYLOAD_BYTES: u32 = 65536;

pub(super) const HDR_LEN: usize = 20;

pub(super) const KERNEL_REPLY_ENDPOINT: u64 = 0x1_0000_0005;

pub(super) struct DecodedResponse<'a> {
    pub op: u16,
    pub request_id: u32,
    pub status: i32,
    pub body: &'a [u8],
}

pub(super) fn encode_request(op: u16, flags: u16, request_id: u32, body: &[u8]) -> Vec<u8> {
    let payload_len = body.len() as u32;
    let mut out = Vec::with_capacity(HDR_LEN + body.len());
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(body);
    out
}

pub(super) fn decode_response(buf: &[u8]) -> Option<DecodedResponse<'_>> {
    if buf.len() < HDR_LEN + 4 {
        return None;
    }
    let magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != MAGIC {
        return None;
    }
    let version = u16::from_le_bytes([buf[4], buf[5]]);
    if version != VERSION {
        return None;
    }
    let op = u16::from_le_bytes([buf[6], buf[7]]);
    let request_id = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    let payload_len = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if payload_len > MAX_PAYLOAD_BYTES + 4 {
        return None;
    }
    let total = HDR_LEN.saturating_add(payload_len as usize);
    if buf.len() < total || (payload_len as usize) < 4 {
        return None;
    }
    let status =
        i32::from_le_bytes([buf[HDR_LEN], buf[HDR_LEN + 1], buf[HDR_LEN + 2], buf[HDR_LEN + 3]]);
    let body = &buf[HDR_LEN + 4..total];
    Some(DecodedResponse { op, request_id, status, body })
}
