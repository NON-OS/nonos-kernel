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

//! 24-byte v2 capsule envelope. Adds an explicit `reply_port` over
//! the original 20-byte v1 layout so the receiver knows where to
//! deliver the response — required for userland-to-userland IPC
//! where the caller is not a kernel-side client with a baked
//! reply slot. v1 capsules see a v2 header as "version mismatch"
//! and refuse it cleanly; v2-aware capsules accept both shapes
//! and route the reply accordingly.
//!
//!   u32 magic            (0..4)
//!   u16 version          (4..6)  — 2 for this shape
//!   u16 op               (6..8)
//!   u16 flags            (8..10)
//!   u16 _reserved        (10..12)
//!   u32 reply_port       (12..16)
//!   u32 request_id       (16..20)
//!   u32 payload_len      (20..24)

use super::wire::{le_u16, le_u32};

pub const VERSION_V2: u16 = 2;
pub const HDR_LEN_V2: usize = 24;

#[derive(Clone, Copy, Debug)]
pub struct RequestV2 {
    pub magic: u32,
    pub op: u16,
    pub flags: u16,
    pub reply_port: u32,
    pub request_id: u32,
    pub payload_len: u32,
}

pub fn write_request_v2(out: &mut [u8], r: &RequestV2) {
    debug_assert!(out.len() >= HDR_LEN_V2);
    out[0..4].copy_from_slice(&r.magic.to_le_bytes());
    out[4..6].copy_from_slice(&VERSION_V2.to_le_bytes());
    out[6..8].copy_from_slice(&r.op.to_le_bytes());
    out[8..10].copy_from_slice(&r.flags.to_le_bytes());
    out[10..12].copy_from_slice(&0u16.to_le_bytes());
    out[12..16].copy_from_slice(&r.reply_port.to_le_bytes());
    out[16..20].copy_from_slice(&r.request_id.to_le_bytes());
    out[20..24].copy_from_slice(&r.payload_len.to_le_bytes());
}

pub fn read_request_v2(bytes: &[u8]) -> Option<RequestV2> {
    if bytes.len() < HDR_LEN_V2 {
        return None;
    }
    let magic = le_u32(bytes, 0)?;
    let version = le_u16(bytes, 4)?;
    if version != VERSION_V2 {
        return None;
    }
    let op = le_u16(bytes, 6)?;
    let flags = le_u16(bytes, 8)?;
    let reply_port = le_u32(bytes, 12)?;
    let request_id = le_u32(bytes, 16)?;
    let payload_len = le_u32(bytes, 20)?;
    Some(RequestV2 { magic, op, flags, reply_port, request_id, payload_len })
}
