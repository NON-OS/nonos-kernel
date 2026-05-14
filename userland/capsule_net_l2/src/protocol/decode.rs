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

use super::errno::{E_BAD_LEN, E_BAD_MAGIC, E_BAD_VERSION};
use super::header::{Request, HDR_LEN, MAGIC, VERSION};

// Parse the v1 envelope. Returns the request descriptor on
// success or a wire errno the caller writes back on the
// response header. The payload buffer is returned by slicing
// the input at the header boundary.
pub fn parse(bytes: &[u8]) -> Result<(Request, &[u8]), u16> {
    if bytes.len() < HDR_LEN {
        return Err(E_BAD_LEN);
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != MAGIC {
        return Err(E_BAD_MAGIC);
    }
    let version = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if version != VERSION {
        return Err(E_BAD_VERSION);
    }
    let op = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    let flags = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    // bytes[10..12] reserved
    let request_id = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let payload_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let want = HDR_LEN + payload_len as usize;
    if bytes.len() < want {
        return Err(E_BAD_LEN);
    }
    Ok((Request { op, flags, request_id, payload_len }, &bytes[HDR_LEN..want]))
}
