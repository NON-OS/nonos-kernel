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

use crate::ip_client::UdpInbound;
use crate::protocol::{E_BAD_LEN, E_NO_PORT, E_RX_EMPTY, OP_RECV};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::STATE;

use super::deliver::deliver;
use super::drain::drain_one;

// Body request: 2-byte local_port (LE).
pub fn handle(sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() < 2 {
        let _ = respond(sender_pid, OP_RECV, E_BAD_LEN, req.request_id, 0, tx);
        return;
    }
    let port = u16::from_le_bytes([body[0], body[1]]);
    if STATE.binds.lock().find_owned_mut(sender_pid, port).is_none() {
        let _ = respond(sender_pid, OP_RECV, E_NO_PORT, req.request_id, 0, tx);
        return;
    }
    if let Some(seg) = dequeue(sender_pid, port) {
        deliver(sender_pid, req, seg, tx);
        return;
    }
    drain_one();
    if let Some(seg) = dequeue(sender_pid, port) {
        deliver(sender_pid, req, seg, tx);
        return;
    }
    let _ = respond(sender_pid, OP_RECV, E_RX_EMPTY, req.request_id, 0, tx);
}

fn dequeue(pid: u32, port: u16) -> Option<UdpInbound> {
    STATE.binds.lock().find_owned_mut(pid, port).and_then(|b| b.pop())
}
