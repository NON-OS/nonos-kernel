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
use super::super::protocol::{encode_request, MAX_DATA_BYTES, OP_READ};
use super::errno::map_status;
use super::seq::next_request_id;
use super::transport::round_trip;

pub fn read(fd: u32, max: usize) -> Result<Vec<u8>, VfsCapsuleError> {
    let pid = gate_caller()?;
    if max > MAX_DATA_BYTES as usize {
        return Err(VfsCapsuleError::OversizedRequest);
    }
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&pid.to_le_bytes());
    body.extend_from_slice(&fd.to_le_bytes());
    body.extend_from_slice(&(max as u32).to_le_bytes());

    let request_id = next_request_id();
    let frame = encode_request(OP_READ, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    Ok(resp.body)
}
