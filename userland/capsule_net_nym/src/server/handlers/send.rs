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

use crate::packet;
use crate::protocol::{
    E_BAD_LEN, E_CRYPTO, E_NO_SESSION, E_NO_UDP, E_OK, MIX_PAYLOAD_MAX, OP_SEND,
};
use crate::server::handlers::io::u32_at;
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::setup;
use crate::state::TABLE;
use crate::udp_client;

pub fn handle(pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let session_id = match u32_at(body, 0) {
        Ok(id) => id,
        Err(e) => return respond(pid, OP_SEND, e, req.request_id, 0, tx),
    };
    let payload = &body[4..];
    if payload.len() > MIX_PAYLOAD_MAX {
        return respond(pid, OP_SEND, E_BAD_LEN, req.request_id, 0, tx);
    }
    let errno = send_payload(pid, session_id, payload, 0, tx);
    respond(pid, OP_SEND, errno, req.request_id, 0, tx);
}

pub(super) fn send_payload(pid: u32, id: u32, payload: &[u8], flags: u8, buf: &mut [u8]) -> u16 {
    let udp_port = setup::udp_port();
    if udp_port == 0 {
        return E_NO_UDP;
    }
    TABLE
        .lock()
        .with_mut(pid, id, |s| {
            let Ok(n) = packet::encode(s.id, flags, &s.key, payload, buf) else { return E_CRYPTO };
            udp_client::send_to(
                udp_port,
                s.gateway.local_port,
                s.gateway.ip,
                s.gateway.port,
                &buf[..n],
            )
            .map_or(E_NO_UDP, |_| E_OK)
        })
        .map_or(E_NO_SESSION, |errno| errno)
}
