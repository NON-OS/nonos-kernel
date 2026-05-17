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
use super::super::error::DriverRtl8169Error;
use super::super::protocol::{encode_request, MAC_LEN, OP_MAC_ADDRESS};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

pub fn mac_address() -> Result<[u8; MAC_LEN], DriverRtl8169Error> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_MAC_ADDRESS, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    if resp.body.len() < MAC_LEN {
        return Err(DriverRtl8169Error::ProtocolMismatch);
    }
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&resp.body[..MAC_LEN]);
    Ok(out)
}
