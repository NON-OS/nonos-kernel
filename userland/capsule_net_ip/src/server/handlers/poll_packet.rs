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

use core::sync::atomic::Ordering;

use crate::ingress::{from_frame, IngressError, Inbound};
use crate::l2_client::{poll_frame, RxError};
use crate::protocol::{E_BAD_PACKET, E_L2_FAULT, E_NO_CONFIG, E_OK, E_RX_EMPTY, OP_POLL_PACKET};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::IFACE;

const HDR_LEN: usize = 20;

// Response body on success: 4 src + 4 dst + 1 proto + payload.
pub fn handle(sender_pid: u32, req: &Request, tx: &mut [u8]) {
    let l2 = IFACE.l2_service_port.load(Ordering::Acquire);
    if l2 == 0 {
        let _ = respond(sender_pid, OP_POLL_PACKET, E_NO_CONFIG, req.request_id, 0, tx);
        return;
    }
    let frame = match poll_frame(l2) {
        Ok(f) => f,
        Err(RxError::Empty) => {
            let _ = respond(sender_pid, OP_POLL_PACKET, E_RX_EMPTY, req.request_id, 0, tx);
            return;
        }
        Err(_) => {
            let _ = respond(sender_pid, OP_POLL_PACKET, E_L2_FAULT, req.request_id, 0, tx);
            return;
        }
    };
    match from_frame(&frame) {
        Ok(p) => deliver(sender_pid, req, p, tx),
        Err(IngressError::NotIpv4) | Err(IngressError::NotForUs) => {
            let _ = respond(sender_pid, OP_POLL_PACKET, E_RX_EMPTY, req.request_id, 0, tx);
        }
        Err(_) => {
            let _ = respond(sender_pid, OP_POLL_PACKET, E_BAD_PACKET, req.request_id, 0, tx);
        }
    }
}

fn deliver(sender_pid: u32, req: &Request, p: Inbound, tx: &mut [u8]) {
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
