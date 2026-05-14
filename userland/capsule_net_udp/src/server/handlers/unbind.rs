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

use crate::protocol::{E_BAD_LEN, E_NO_PORT, E_OK, OP_UNBIND};
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::state::{TableError, STATE};

// Body: 2-byte local port (LE).
pub fn handle(sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() < 2 {
        let _ = respond(sender_pid, OP_UNBIND, E_BAD_LEN, req.request_id, 0, tx);
        return;
    }
    let port = u16::from_le_bytes([body[0], body[1]]);
    let errno = match STATE.binds.lock().remove(sender_pid, port) {
        Ok(()) => E_OK,
        Err(TableError::NotFound) | Err(TableError::InUse) | Err(TableError::Full) => E_NO_PORT,
    };
    let _ = respond(sender_pid, OP_UNBIND, errno, req.request_id, 0, tx);
}
