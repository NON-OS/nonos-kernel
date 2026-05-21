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
    let op = match u16_at(buf, 6) {
        Some(v) => v,
        None => return Err((E_BAD_LEN, Request { op: 0, flags: 0, request_id: 0 })),
    };
    let flags = match u16_at(buf, 8) {
        Some(v) => v,
        None => return Err((E_BAD_LEN, Request { op: 0, flags: 0, request_id: 0 })),
    };
    let request_id = match u32_at(buf, 12) {
        Some(v) => v,
        None => return Err((E_BAD_LEN, Request { op: 0, flags: 0, request_id: 0 })),
    };
    let req = Request { op, flags, request_id };
    let Some(magic) = u32_at(buf, 0) else {
        return Err((E_BAD_LEN, req));
    };
    if magic != MAGIC {
        return Err((E_BAD_MAGIC, req));
    }
    let Some(version) = u16_at(buf, 4) else {
        return Err((E_BAD_LEN, req));
    };
    if version != VERSION {
        return Err((E_BAD_VERSION, req));
    }
    let Some(payload_len) = u32_at(buf, 16) else {
        return Err((E_BAD_LEN, req));
    };
    let end = match HDR_LEN.checked_add(payload_len as usize) {
        Some(end) if end == buf.len() => end,
        _ => return Err((E_BAD_LEN, req)),
    };
    Ok((req, &buf[HDR_LEN..end]))
}

fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}
