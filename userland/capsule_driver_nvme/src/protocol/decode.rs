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

use super::header::{Request, HDR_LEN, MAGIC, VERSION};

pub fn decode_request(buf: &[u8]) -> Option<Request> {
    if buf.len() < HDR_LEN {
        return None;
    }
    if u32::from_le_bytes(buf[0..4].try_into().ok()?) != MAGIC {
        return None;
    }
    if u16::from_le_bytes(buf[4..6].try_into().ok()?) != VERSION {
        return None;
    }
    Some(Request {
        op: u16::from_le_bytes(buf[6..8].try_into().ok()?),
        flags: u16::from_le_bytes(buf[8..10].try_into().ok()?),
        request_id: u32::from_le_bytes(buf[12..16].try_into().ok()?),
        payload_len: u32::from_le_bytes(buf[16..20].try_into().ok()?),
    })
}
