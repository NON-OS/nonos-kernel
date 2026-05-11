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

//! `OP_LINK_STATUS`. Returns true if the device reports link up.
//! The userland handler samples STATUS.LU on every call so a
//! topology change between two probes is observable here.

use super::super::capability::gate_call;
use super::super::error::DriverNetError;
use super::super::protocol::{encode_request, OP_LINK_STATUS};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

pub fn link_status() -> Result<bool, DriverNetError> {
    let _caller = gate_call()?;
    let body: [u8; 0] = [];
    let request_id = next_request_id();
    let frame = encode_request(OP_LINK_STATUS, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    if resp.body.is_empty() {
        return Err(DriverNetError::ProtocolMismatch);
    }
    Ok(resp.body[0] != 0)
}
