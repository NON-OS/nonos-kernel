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
use super::super::error::MarketError;
use super::super::protocol::{encode_request, OP_LOAD_INDEX};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

/// Hand a signed marketplace index blob to the userland capsule.
/// Acceptance is determined entirely on the userland side: bound
/// decode, bootstrap-trust pubkey check, Ed25519 verification
/// through the kernel-routed crypto syscall, and serial monotonic
/// guard. The kernel client just transports the bytes and lifts
/// the response status.
pub fn load_index(blob: &[u8]) -> Result<(), MarketError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_LOAD_INDEX, 0, request_id, blob);
    let resp = round_trip(request_id, frame)?;
    if resp.status == 0 {
        Ok(())
    } else {
        Err(lift(resp.status))
    }
}
