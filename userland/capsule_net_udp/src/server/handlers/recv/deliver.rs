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
use crate::protocol::{E_NO_IP_LINK, E_OK, E_RX_EMPTY, OP_RECV};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::udp::parse as udp_parse;

const HDR_LEN: usize = 20;

// Response body: 4 src IPv4 + 2 src_port + payload bytes.
pub fn deliver(sender_pid: u32, req: &Request, seg: UdpInbound, tx: &mut [u8]) {
    let (h, payload) = match udp_parse(&seg.src, &seg.dst, &seg.segment) {
        Ok(v) => v,
        Err(_) => {
            let _ = respond(sender_pid, OP_RECV, E_NO_IP_LINK, req.request_id, 0, tx);
            return;
        }
    };
    let body_len = 4 + 2 + payload.len();
    if HDR_LEN + body_len > tx.len() {
        let _ = respond(sender_pid, OP_RECV, E_RX_EMPTY, req.request_id, 0, tx);
        return;
    }
    let mut cur = HDR_LEN;
    tx[cur..cur + 4].copy_from_slice(&seg.src);
    cur += 4;
    tx[cur..cur + 2].copy_from_slice(&h.src_port.to_le_bytes());
    cur += 2;
    tx[cur..cur + payload.len()].copy_from_slice(payload);
    let _ = respond(sender_pid, OP_RECV, E_OK, req.request_id, body_len as u32, tx);
}
