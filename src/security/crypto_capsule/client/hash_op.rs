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

//! Shared body for the four hash ops the crypto capsule serves
//! (BLAKE3, SHA3-256, SHA-256, SHA-512). Each op differs only by its
//! protocol opcode and digest length, both lifted into generics so
//! per-op files become a single function call. Cap-gated by
//! `CAP_CRYPTO`; oversize input is rejected before the round-trip.

use super::super::capability::gate_hash;
use super::super::error::CryptoCapsuleError;
use super::super::protocol::{encode_request, MAX_INPUT_BYTES};
use super::seq::next_request_id;
use super::transport::round_trip;

pub(super) fn fixed_size_hash<const N: usize>(
    op: u16,
    input: &[u8],
) -> Result<[u8; N], CryptoCapsuleError> {
    gate_hash()?;
    if input.len() > MAX_INPUT_BYTES as usize {
        return Err(CryptoCapsuleError::OversizedRequest);
    }
    let request_id = next_request_id();
    let frame = encode_request(op, 0, request_id, input);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() != N {
        return Err(CryptoCapsuleError::ProtocolMismatch);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&resp.body);
    Ok(out)
}

pub(super) fn map_status(status: i32) -> CryptoCapsuleError {
    match status {
        -22 => CryptoCapsuleError::InvalidArgument,
        -90 => CryptoCapsuleError::OversizedRequest,
        -13 => CryptoCapsuleError::AccessDenied,
        _ => CryptoCapsuleError::TransportFailure,
    }
}
