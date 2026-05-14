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

use crate::egress::{send as egress_send, EgressError};
use crate::protocol::{
    E_BAD_LEN, E_L2_FAULT, E_NO_CONFIG, E_NO_NEIGHBOUR, E_NO_ROUTE, E_OK, OP_SEND_PACKET,
};
use crate::server::parse_req::Request;
use crate::server::respond::respond;

// Body: 4 dst IPv4 + 1 protocol + payload.
pub fn handle(sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() < 5 {
        let _ = respond(sender_pid, OP_SEND_PACKET, E_BAD_LEN, req.request_id, 0, tx);
        return;
    }
    let mut dst = [0u8; 4];
    dst.copy_from_slice(&body[0..4]);
    let protocol = body[4];
    let payload = &body[5..];
    let errno = match egress_send(dst, protocol, payload) {
        Ok(()) => E_OK,
        Err(EgressError::NoConfig) => E_NO_CONFIG,
        Err(EgressError::NoRoute) => E_NO_ROUTE,
        Err(EgressError::NoNeighbour) => E_NO_NEIGHBOUR,
        Err(EgressError::L2Failed) | Err(EgressError::Build) => E_L2_FAULT,
    };
    let _ = respond(sender_pid, OP_SEND_PACKET, errno, req.request_id, 0, tx);
}
