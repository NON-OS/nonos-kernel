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

use super::types::{HDR_LEN, MAGIC, VERSION};

// Encode a response frame. Layout matches `decode_request` exactly so
// the kernel-side decoder accepts it without special-casing. Status
// rides in the first 4 bytes of the payload as a little-endian i32;
// the rest of the payload is op-specific.
pub fn encode_response(op: u16, flags: u16, request_id: u32, status: i32, body: &[u8]) -> Vec<u8> {
    let payload_len = (4 + body.len()) as u32;
    let mut out = Vec::with_capacity(HDR_LEN + payload_len as usize);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&op.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&request_id.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(body);
    out
}
