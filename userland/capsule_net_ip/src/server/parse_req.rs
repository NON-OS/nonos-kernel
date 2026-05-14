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

use crate::protocol::{E_BAD_LEN, E_BAD_MAGIC, E_BAD_VERSION, MAGIC};

pub const HDR_LEN: usize = 20;

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub op: u16,
    pub flags: u16,
    pub request_id: u32,
    pub payload_len: u32,
}

pub fn parse(buf: &[u8]) -> Result<(Request, &[u8]), u16> {
    if buf.len() < HDR_LEN {
        return Err(E_BAD_LEN);
    }
    if u32::from_le_bytes(buf[0..4].try_into().unwrap()) != MAGIC {
        return Err(E_BAD_MAGIC);
    }
    if u16::from_le_bytes(buf[4..6].try_into().unwrap()) != 1 {
        return Err(E_BAD_VERSION);
    }
    let op = u16::from_le_bytes(buf[6..8].try_into().unwrap());
    let flags = u16::from_le_bytes(buf[8..10].try_into().unwrap());
    let request_id = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let payload_len = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let want = HDR_LEN + payload_len as usize;
    if buf.len() < want {
        return Err(E_BAD_LEN);
    }
    Ok((Request { op, flags, request_id, payload_len }, &buf[HDR_LEN..want]))
}
