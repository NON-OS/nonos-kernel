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

use alloc::vec;
use nonos_libc::mk_ipc_recv_from;

use crate::protocol::E_BAD_OP;
use crate::server::handlers;
use crate::server::parse_req::{parse, HDR_LEN};
use crate::server::respond::respond;

const SERVICE_INBOX: u64 = 0;
const BUF_LEN: usize = HDR_LEN + 1536;

pub fn run() -> ! {
    let mut rx = vec![0u8; BUF_LEN];
    let mut tx = vec![0u8; BUF_LEN];
    loop {
        let mut sender = 0u32;
        let n = mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), rx.len(), 0, &mut sender);
        if n <= 0 || sender == 0 {
            continue;
        }
        let Ok((req, body)) = parse(&rx[..n as usize]) else { continue };
        if !handlers::dispatch(sender, &req, body, &mut tx) {
            respond(sender, req.op, E_BAD_OP, req.request_id, 0, &mut tx);
        }
    }
}
