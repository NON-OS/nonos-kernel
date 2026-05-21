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

use super::super::capability::gate_hash;
use super::super::error::CryptoCapsuleError;
use super::super::protocol::encode_request;
use super::seq::next_request_id;
use super::transport::round_trip;

pub(super) fn fixed32(op: u16, body: &[u8]) -> Result<[u8; 32], CryptoCapsuleError> {
    let out = variable(op, body, 32)?;
    let mut fixed = [0u8; 32];
    fixed.copy_from_slice(&out);
    Ok(fixed)
}

pub(super) fn variable(
    op: u16,
    body: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, CryptoCapsuleError> {
    gate_hash()?;
    let request_id = next_request_id();
    let frame = encode_request(op, 0, request_id, body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() != out_len {
        return Err(CryptoCapsuleError::ProtocolMismatch);
    }
    Ok(resp.body)
}

fn map_status(status: i32) -> CryptoCapsuleError {
    match status {
        -13 => CryptoCapsuleError::AccessDenied,
        -22 => CryptoCapsuleError::InvalidArgument,
        -90 => CryptoCapsuleError::OversizedRequest,
        _ => CryptoCapsuleError::TransportFailure,
    }
}
