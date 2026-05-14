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

use crate::dhcp::State as ClientState;
use crate::protocol::{E_OK, OP_LEASE_STATUS};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::STATE;

// Body layout: 1 byte state code + 4 IPv4 + 1 prefix + 4 gateway
// + 4 DNS + 4 lease seconds (LE) = 18 bytes.
const BODY_LEN: u32 = 18;
const HDR_LEN: usize = 20;

pub fn handle(sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let state_code: u8 = match *STATE.client_state.lock() {
        ClientState::Init => 0,
        ClientState::Selecting => 1,
        ClientState::Requesting => 2,
        ClientState::Bound => 3,
        ClientState::Renewing => 4,
    };
    let lease = *STATE.lease.lock();
    let mut cur = HDR_LEN;
    tx[cur] = state_code;
    cur += 1;
    tx[cur..cur + 4].copy_from_slice(&lease.ipv4);
    cur += 4;
    tx[cur] = lease.prefix;
    cur += 1;
    tx[cur..cur + 4].copy_from_slice(&lease.gateway);
    cur += 4;
    tx[cur..cur + 4].copy_from_slice(&lease.dns);
    cur += 4;
    tx[cur..cur + 4].copy_from_slice(&lease.lease_seconds.to_le_bytes());
    let _ = respond(sender_pid, OP_LEASE_STATUS, E_OK, req.request_id, BODY_LEN, tx);
}
