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

use crate::packet::FLAG_REPLY;
use crate::protocol::{E_BAD_LEN, E_NO_SESSION, MIX_PAYLOAD_MAX, OP_SEND_REPLY};
use crate::server::handlers::io::u32_at;
use crate::server::handlers::send::send_payload;
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state;

pub fn handle(pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let surb = match u32_at(body, 0) {
        Ok(surb) => surb,
        Err(e) => return respond(pid, OP_SEND_REPLY, e, req.request_id, 0, tx),
    };
    let payload = &body[4..];
    if payload.len() > MIX_PAYLOAD_MAX {
        return respond(pid, OP_SEND_REPLY, E_BAD_LEN, req.request_id, 0, tx);
    }
    let Some(session) = state::session_for_surb(pid, surb) else {
        return respond(pid, OP_SEND_REPLY, E_NO_SESSION, req.request_id, 0, tx);
    };
    let errno = send_payload(pid, session, payload, FLAG_REPLY, tx);
    respond(pid, OP_SEND_REPLY, errno, req.request_id, 0, tx);
}
