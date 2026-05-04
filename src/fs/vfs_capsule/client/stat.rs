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
use super::super::protocol::{encode_request, MAX_PATH_BYTES, OP_STAT};
use super::errno::map_status;
use super::seq::next_request_id;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy)]
pub struct StatInfo {
    pub size: u64,
    pub flags: u32,
}

pub fn stat(path: &str) -> Result<StatInfo, VfsCapsuleError> {
    let pid = gate_caller()?;
    let path_bytes = path.as_bytes();
    if path_bytes.is_empty() || path_bytes.len() > MAX_PATH_BYTES as usize {
        return Err(VfsCapsuleError::InvalidArgument);
    }
    let mut body = Vec::with_capacity(5 + path_bytes.len());
    body.extend_from_slice(&pid.to_le_bytes());
    body.push(path_bytes.len() as u8);
    body.extend_from_slice(path_bytes);

    let request_id = next_request_id();
    let frame = encode_request(OP_STAT, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() != 12 {
        return Err(VfsCapsuleError::ProtocolMismatch);
    }
    let b = &resp.body;
    let size = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    let flags = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
    Ok(StatInfo { size, flags })
}
