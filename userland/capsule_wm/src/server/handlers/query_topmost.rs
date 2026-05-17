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

use nonos_libc::mk_ipc_send_to_pid;

use crate::focus::topmost_at;
use crate::protocol::{
    response_header, write_status, Request, E_INVAL, HDR_LEN, QUERY_TOPMOST_REQ_LEN,
    QUERY_TOPMOST_RESP_LEN, STATUS_LEN,
};
use crate::server::respond;
use crate::state::Context;

// input_router calls this on pointer events to resolve hit-test
// against the live wm window table. Returns (owner_pid, window_id)
// of the topmost visible focusable window at (x, y), or (0, 0)
// when nothing is hit (status still 0).
pub fn handle(ctx: &mut Context, sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    if body.len() != QUERY_TOPMOST_REQ_LEN {
        let _ = respond::status(sender_pid, req, E_INVAL, tx);
        return;
    }
    let x = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let y = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let (owner, wid) = topmost_at(&ctx.windows, x, y).unwrap_or((0, 0));
    let off = HDR_LEN + STATUS_LEN;
    tx[off..off + 4].copy_from_slice(&owner.to_le_bytes());
    tx[off + 4..off + 8].copy_from_slice(&wid.to_le_bytes());
    response_header(tx, req, (STATUS_LEN + QUERY_TOPMOST_RESP_LEN) as u32);
    write_status(tx, 0);
    let _ = mk_ipc_send_to_pid(sender_pid, tx.as_ptr(), HDR_LEN + STATUS_LEN + QUERY_TOPMOST_RESP_LEN);
}
