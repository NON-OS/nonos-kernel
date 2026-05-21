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

use nonos_libc::mk_yield;

use crate::protocol::{E_BAD_LEN, E_OK, E_RX_EMPTY, OP_ACCEPT};
use crate::server::handlers::io::u32_at;
use crate::server::parse_req::Request;
use crate::server::respond::respond;
use crate::server::tcp_rx;
use crate::state::TABLE;

const WAIT_TRIES: usize = 32;

pub fn handle(sender_pid: u32, req: &Request, body: &[u8], tx: &mut [u8]) {
    let handle = match u32_at(body, 0) {
        Ok(h) => h,
        Err(_) => return status(sender_pid, req, E_BAD_LEN, tx),
    };
    for _ in 0..WAIT_TRIES {
        if let Some(child) = pop_accept(sender_pid, handle) {
            return answer(sender_pid, req, child, tx);
        }
        tcp_rx::drain_one();
        mk_yield();
    }
    status(sender_pid, req, E_RX_EMPTY, tx);
}

fn pop_accept(owner: u32, handle: u32) -> Option<u32> {
    TABLE.lock().owned_mut(owner, handle)?.accept.pop_front()
}

fn answer(sender_pid: u32, req: &Request, child: u32, tx: &mut [u8]) {
    tx[20..24].copy_from_slice(&child.to_le_bytes());
    let _ = respond(sender_pid, OP_ACCEPT, E_OK, req.request_id, 4, tx);
}

fn status(sender_pid: u32, req: &Request, errno: u16, tx: &mut [u8]) {
    let _ = respond(sender_pid, OP_ACCEPT, errno, req.request_id, 0, tx);
}
