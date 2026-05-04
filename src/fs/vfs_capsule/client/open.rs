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

use super::super::capability::gate_caller;
use super::super::error::VfsCapsuleError;
use super::super::protocol::{
    encode_request, MAX_PATH_BYTES, OP_OPEN, O_APPEND, O_CREATE, O_TRUNC,
};
use super::errno::map_status;
use super::seq::next_request_id;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    pub create: bool,
    pub truncate: bool,
    pub append: bool,
}

pub fn open(path: &str, flags: OpenFlags) -> Result<u32, VfsCapsuleError> {
    let pid = gate_caller()?;
    let path_bytes = path.as_bytes();
    if path_bytes.is_empty() || path_bytes.len() > MAX_PATH_BYTES as usize {
        return Err(VfsCapsuleError::InvalidArgument);
    }
    let mut body = Vec::with_capacity(4 + 1 + path_bytes.len() + 4);
    body.extend_from_slice(&pid.to_le_bytes());
    body.push(path_bytes.len() as u8);
    body.extend_from_slice(path_bytes);
    let mut f: u32 = 0;
    if flags.create {
        f |= O_CREATE;
    }
    if flags.truncate {
        f |= O_TRUNC;
    }
    if flags.append {
        f |= O_APPEND;
    }
    body.extend_from_slice(&f.to_le_bytes());

    let request_id = next_request_id();
    let frame = encode_request(OP_OPEN, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() != 4 {
        return Err(VfsCapsuleError::ProtocolMismatch);
    }
    Ok(u32::from_le_bytes([resp.body[0], resp.body[1], resp.body[2], resp.body[3]]))
}
