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

use crate::protocol::{E_OK, E_RX_EMPTY, OP_POLL_PACKET};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::Packet;

const HDR_LEN: usize = 20;

pub fn send(sender_pid: u32, req: &Request, p: Packet, tx: &mut [u8]) {
    let body_len = 4 + 4 + 1 + p.payload.len();
    if HDR_LEN + body_len > tx.len() {
        let _ = respond(sender_pid, OP_POLL_PACKET, E_RX_EMPTY, req.request_id, 0, tx);
        return;
    }
    let mut cur = HDR_LEN;
    tx[cur..cur + 4].copy_from_slice(&p.src);
    cur += 4;
    tx[cur..cur + 4].copy_from_slice(&p.dst);
    cur += 4;
    tx[cur] = p.protocol;
    cur += 1;
    tx[cur..cur + p.payload.len()].copy_from_slice(&p.payload);
    let _ = respond(sender_pid, OP_POLL_PACKET, E_OK, req.request_id, body_len as u32, tx);
}
