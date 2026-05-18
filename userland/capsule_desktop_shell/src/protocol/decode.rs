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

use super::{Request, E_BAD_LEN, E_BAD_MAGIC, E_BAD_VERSION, HDR_LEN, MAGIC, VERSION};

pub fn parse(buf: &[u8]) -> Result<(Request, &[u8]), (i32, Request)> {
    if buf.len() < HDR_LEN {
        return Err((E_BAD_LEN, Request { op: 0, flags: 0, request_id: 0 }));
    }
    let op = u16::from_le_bytes(buf[6..8].try_into().unwrap());
    let flags = u16::from_le_bytes(buf[8..10].try_into().unwrap());
    let request_id = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let req = Request { op, flags, request_id };
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err((E_BAD_MAGIC, req));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != VERSION {
        return Err((E_BAD_VERSION, req));
    }
    let payload_len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let end = match HDR_LEN.checked_add(payload_len as usize) {
        Some(end) if end == buf.len() => end,
        _ => return Err((E_BAD_LEN, req)),
    };
    Ok((req, &buf[HDR_LEN..end]))
}
