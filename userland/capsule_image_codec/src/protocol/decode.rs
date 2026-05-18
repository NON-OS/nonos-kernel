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

pub fn parse(buf: &[u8]) -> Result<(Request, &[u8]), (Request, i32)> {
    let mut req = Request {
        op: 0,
        flags: 0,
        request_id: 0,
    };
    if buf.len() < HDR_LEN {
        return Err((req, E_BAD_LEN));
    }
    let magic = match <[u8; 4]>::try_from(&buf[0..4]) {
        Ok(v) => u32::from_le_bytes(v),
        Err(_) => return Err((req, E_BAD_LEN)),
    };
    if magic != MAGIC {
        return Err((req, E_BAD_MAGIC));
    }
    let version = match <[u8; 2]>::try_from(&buf[4..6]) {
        Ok(v) => u16::from_le_bytes(v),
        Err(_) => return Err((req, E_BAD_LEN)),
    };
    req.op = match <[u8; 2]>::try_from(&buf[6..8]) {
        Ok(v) => u16::from_le_bytes(v),
        Err(_) => return Err((req, E_BAD_LEN)),
    };
    req.flags = match <[u8; 2]>::try_from(&buf[8..10]) {
        Ok(v) => u16::from_le_bytes(v),
        Err(_) => return Err((req, E_BAD_LEN)),
    };
    req.request_id = match <[u8; 4]>::try_from(&buf[12..16]) {
        Ok(v) => u32::from_le_bytes(v),
        Err(_) => return Err((req, E_BAD_LEN)),
    };
    if version != VERSION {
        return Err((req, E_BAD_VERSION));
    }
    let payload_len = match <[u8; 4]>::try_from(&buf[16..20]) {
        Ok(v) => u32::from_le_bytes(v),
        Err(_) => return Err((req, E_BAD_LEN)),
    };
    let end = match HDR_LEN.checked_add(payload_len as usize) {
        Some(v) => v,
        None => return Err((req, E_BAD_LEN)),
    };
    if end != buf.len() {
        return Err((req, E_BAD_LEN));
    }
    Ok((req, &buf[HDR_LEN..end]))
}
