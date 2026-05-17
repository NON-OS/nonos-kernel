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
    parse, E_BAD_OP, E_INVAL, HDR_LEN, IPC_PAYLOAD_MAX, OP_ACCEPT_CSW, OP_BUILD_INQUIRY,
    OP_BUILD_READ10, OP_BUILD_READ_CAPACITY10, OP_BUILD_WRITE10, OP_GET_STATE, OP_HEALTHCHECK,
    OP_PROBE_CONFIG,
};
use crate::server::{handlers, respond};
use crate::state::State;

const SERVICE_INBOX: u64 = 0;

pub fn run() -> ! {
    let mut rx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut tx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut state = State::new();
    loop_once(&mut state, &mut rx, &mut tx);
}

fn loop_once(state: &mut State, rx: &mut [u8], tx: &mut [u8]) -> ! {
    loop {
        let mut sender_pid = 0u32;
        let n = mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), rx.len(), 0, &mut sender_pid);
        if n <= 0 || sender_pid == 0 {
            continue;
        }
        let Some((req, body)) = parse(&rx[..n as usize]) else { continue };
        dispatch(state, sender_pid, req, body, tx);
    }
}

fn dispatch(state: &mut State, sender_pid: u32, req: crate::protocol::Request, body: &[u8], tx: &mut [u8]) {
    match req.op {
        OP_HEALTHCHECK if body.is_empty() => handlers::health::handle(sender_pid, &req, tx),
        OP_PROBE_CONFIG => handlers::probe_config::handle(state, sender_pid, &req, body, tx),
        OP_BUILD_INQUIRY if body.is_empty() => handlers::build_inquiry::handle(state, sender_pid, &req, tx),
        OP_BUILD_READ_CAPACITY10 if body.is_empty() => handlers::build_capacity::handle(state, sender_pid, &req, tx),
        OP_BUILD_READ10 => handlers::build_read::handle(state, sender_pid, &req, body, tx),
        OP_BUILD_WRITE10 => handlers::build_write::handle(state, sender_pid, &req, body, tx),
        OP_ACCEPT_CSW => handlers::accept_csw::handle(state, sender_pid, &req, body, tx),
        OP_GET_STATE if body.is_empty() => handlers::get_state::handle(state, sender_pid, &req, tx),
        _ if body.is_empty() => {
            let _ = respond::status(sender_pid, &req, E_BAD_OP, tx);
        }
        _ => {
            let _ = respond::status(sender_pid, &req, E_INVAL, tx);
        }
    }
}
