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

use super::super::capability::gate_call;
use super::super::error::DriverPs2Error;
use super::super::protocol::{encode_request, OP_GET_STATE};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

/// Diagnostic counters the capsule exposes. `events_seen` covers
/// every byte the IRQ drainer absorbed; `events_dropped` increments
/// when the bounded ring overflows; `parity_errors` and
/// `timeout_errors` reflect i8042 status-register flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingState {
    pub events_seen: u64,
    pub events_dropped: u64,
    pub parity_errors: u64,
    pub timeout_errors: u64,
}

const STATE_PAYLOAD_LEN: usize = 32;

pub fn get_state() -> Result<RingState, DriverPs2Error> {
    let _caller = gate_call()?;
    let body: [u8; 0] = [];
    let request_id = next_request_id();
    let frame = encode_request(OP_GET_STATE, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    if resp.body.len() < STATE_PAYLOAD_LEN {
        return Err(DriverPs2Error::ProtocolMismatch);
    }
    Ok(RingState {
        events_seen: u64::from_le_bytes(resp.body[0..8].try_into().unwrap()),
        events_dropped: u64::from_le_bytes(resp.body[8..16].try_into().unwrap()),
        parity_errors: u64::from_le_bytes(resp.body[16..24].try_into().unwrap()),
        timeout_errors: u64::from_le_bytes(resp.body[24..32].try_into().unwrap()),
    })
}
