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

use crate::protocol::{
    E_BAD_OP, OP_HEALTHCHECK, OP_LEASE_RELEASE, OP_LEASE_RENEW, OP_LEASE_REQUEST,
    OP_LEASE_STATUS,
};

use super::handlers;
use super::parse_req::{parse, HDR_LEN};
use super::respond::respond;

const SERVICE_INBOX: u64 = 0;
const RX_LEN: usize = HDR_LEN + 256;
const TX_LEN: usize = HDR_LEN + 256;

pub fn run() -> ! {
    let mut rx = vec![0u8; RX_LEN];
    let mut tx = vec![0u8; TX_LEN];
    loop {
        let mut sender_pid: u32 = 0;
        let n = mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), RX_LEN, 0, &mut sender_pid);
        if n <= 0 || sender_pid == 0 {
            continue;
        }
        let len = n as usize;
        let Ok((req, _body)) = parse(&rx[..len]) else { continue };
        match req.op {
            OP_HEALTHCHECK => handlers::health::handle(sender_pid, &req, &mut tx),
            OP_LEASE_REQUEST => handlers::lease_request::handle(sender_pid, &req, &mut tx),
            OP_LEASE_STATUS => handlers::lease_status::handle(sender_pid, &req, &mut tx),
            OP_LEASE_RENEW => handlers::lease_renew::handle(sender_pid, &req, &mut tx),
            OP_LEASE_RELEASE => handlers::lease_release::handle(sender_pid, &req, &mut tx),
            _ => {
                let _ = respond(sender_pid, req.op, E_BAD_OP, req.request_id, 0, &mut tx);
            }
        }
    }
}
