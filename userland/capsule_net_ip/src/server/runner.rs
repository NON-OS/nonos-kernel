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
    E_BAD_OP, IPC_PAYLOAD_MAX, OP_GET_CONFIG, OP_HEALTHCHECK, OP_POLL_PACKET, OP_ROUTE_ADD,
    OP_ROUTE_CLEAR, OP_SEND_PACKET, OP_SET_CONFIG,
};

use super::handlers;
use super::parse_req::{parse, HDR_LEN};
use super::respond::respond;

const SERVICE_INBOX: u64 = 0;

pub fn run() -> ! {
    let rx_len = HDR_LEN + IPC_PAYLOAD_MAX;
    let tx_len = HDR_LEN + IPC_PAYLOAD_MAX;
    let mut rx = vec![0u8; rx_len];
    let mut tx = vec![0u8; tx_len];
    loop {
        let mut sender_pid: u32 = 0;
        let n = mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), rx_len, 0, &mut sender_pid);
        if n <= 0 || sender_pid == 0 {
            continue;
        }
        let len = n as usize;
        let Ok((req, body)) = parse(&rx[..len]) else { continue };
        match req.op {
            OP_HEALTHCHECK => handlers::health::handle(sender_pid, &req, &mut tx),
            OP_GET_CONFIG => handlers::get_config::handle(sender_pid, &req, &mut tx),
            OP_SET_CONFIG => handlers::set_config::handle(sender_pid, &req, body, &mut tx),
            OP_SEND_PACKET => handlers::send_packet::handle(sender_pid, &req, body, &mut tx),
            OP_POLL_PACKET => handlers::poll_packet::handle(sender_pid, &req, &mut tx),
            OP_ROUTE_ADD => handlers::route_add::handle(sender_pid, &req, body, &mut tx),
            OP_ROUTE_CLEAR => handlers::route_clear::handle(sender_pid, &req, &mut tx),
            _ => {
                let _ = respond(sender_pid, req.op, E_BAD_OP, req.request_id, 0, &mut tx);
            }
        }
    }
}
