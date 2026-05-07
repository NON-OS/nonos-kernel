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
use super::super::error::DriverNetError;
use super::super::protocol::{encode_request, OP_HEALTHCHECK};
use super::seq::next_request_id;
use super::transport::round_trip;

/// Probe the capsule. Returns `Ok(())` only when the round trip
/// completes and the capsule reports status 0.
pub fn healthcheck() -> Result<(), DriverNetError> {
    let _caller = gate_call()?;
    let body: [u8; 0] = [];
    let request_id = next_request_id();
    let frame = encode_request(OP_HEALTHCHECK, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(DriverNetError::DeviceFailure);
    }
    Ok(())
}
