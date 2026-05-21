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

use super::wire::{IP_HDR_LEN, IP_MAGIC, IP_VERSION};

pub fn write_request(out: &mut [u8], op: u16, request_id: u32, payload_len: u32) {
    out[0..4].copy_from_slice(&IP_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&IP_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&op.to_le_bytes());
    out[8..12].fill(0);
    out[12..16].copy_from_slice(&request_id.to_le_bytes());
    out[16..20].copy_from_slice(&payload_len.to_le_bytes());
}

pub fn parse_response(buf: &[u8]) -> Option<(u16, u16, u32, u32)> {
    if buf.len() < IP_HDR_LEN {
        return None;
    }
    if u32::from_le_bytes(buf[0..4].try_into().ok()?) != IP_MAGIC {
        return None;
    }
    if u16::from_le_bytes(buf[4..6].try_into().ok()?) != IP_VERSION {
        return None;
    }
    let op = u16::from_le_bytes(buf[6..8].try_into().ok()?);
    let errno = u16::from_le_bytes(buf[8..10].try_into().ok()?);
    let rid = u32::from_le_bytes(buf[12..16].try_into().ok()?);
    let len = u32::from_le_bytes(buf[16..20].try_into().ok()?);
    Some((op, errno, rid, len))
}
