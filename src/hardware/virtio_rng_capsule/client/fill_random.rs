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

use super::super::capability::gate_read;
use super::super::error::DriverRngError;
use super::super::protocol::{encode_request, MAX_FILL_BYTES, OP_FILL_RANDOM};
use super::seq::next_request_id;
use super::transport::round_trip;

/// Fill `out` with random bytes from the virtio-rng driver capsule.
/// Returns the count written on success. Cap-gated by `CAP_DRIVER`;
/// over-sized requests are refused without round-tripping so a
/// caller cannot starve the queue with a bogus length.
pub fn fill_random(out: &mut [u8]) -> Result<usize, DriverRngError> {
    let _caller = gate_read()?;
    if out.len() > MAX_FILL_BYTES as usize {
        return Err(DriverRngError::OversizedRequest);
    }
    if out.is_empty() {
        return Err(DriverRngError::InvalidArgument);
    }
    let length = out.len() as u32;
    let body: [u8; 0] = [];
    let request_id = next_request_id();
    let frame = encode_request(OP_FILL_RANDOM, 0, request_id, &body);
    // The userland capsule reads `payload_len` from the header to
    // size the buffer the device fills, so the length we want lives
    // in the header — `body` itself is empty.
    let frame = with_payload_len(frame, length);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(map_status(resp.status));
    }
    if resp.body.len() != out.len() {
        return Err(DriverRngError::DeviceFailure);
    }
    out.copy_from_slice(&resp.body);
    Ok(out.len())
}

fn with_payload_len(mut frame: alloc::vec::Vec<u8>, payload_len: u32) -> alloc::vec::Vec<u8> {
    // payload_len lives at offset 16 in the v1 envelope.
    if frame.len() >= 20 {
        frame[16..20].copy_from_slice(&payload_len.to_le_bytes());
    }
    frame
}

fn map_status(status: i32) -> DriverRngError {
    match status {
        -22 => DriverRngError::InvalidArgument,
        -90 => DriverRngError::OversizedRequest,
        -5 => DriverRngError::DeviceFailure,
        -13 => DriverRngError::AccessDenied,
        _ => DriverRngError::TransportFailure,
    }
}
