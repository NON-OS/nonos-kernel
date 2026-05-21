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

use crate::crypto::fill_random;
use crate::packet::FLAG_COVER;
use crate::protocol::{COVER_BYTES, E_CRYPTO, OP_COVER_TICK};
use crate::server::handlers::io::u32_at;
use crate::server::handlers::send::send_payload;
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state;

pub fn handle(pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let session_id = match u32_at(body, 0) {
        Ok(id) => id,
        Err(e) => {
            respond(pid, OP_COVER_TICK, e, req.request_id, 0, tx);
            return;
        }
    };
    match state::cover_due() {
        Ok(true) => {}
        Ok(false) => {
            respond(pid, OP_COVER_TICK, 0, req.request_id, 0, tx);
            return;
        }
        Err(_) => {
            respond(pid, OP_COVER_TICK, E_CRYPTO, req.request_id, 0, tx);
            return;
        }
    }
    let policy = state::timing_policy();
    for _ in 0..policy.cover_burst {
        let mut cover = [0u8; COVER_BYTES];
        if fill_random(&mut cover).is_err() {
            respond(pid, OP_COVER_TICK, E_CRYPTO, req.request_id, 0, tx);
            return;
        }
        let errno = send_payload(pid, session_id, &cover, FLAG_COVER, tx);
        if errno != 0 {
            respond(pid, OP_COVER_TICK, errno, req.request_id, 0, tx);
            return;
        }
    }
    respond(pid, OP_COVER_TICK, 0, req.request_id, 0, tx);
}
