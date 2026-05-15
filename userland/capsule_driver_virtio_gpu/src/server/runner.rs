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

use crate::driver::Driver;
use crate::protocol::{
    parse, E_BAD_OP, E_INVAL, HDR_LEN, IPC_PAYLOAD_MAX, OP_ATTACH_BACKING, OP_CONTROLLER_INFO,
    OP_CONTROLQ_STATE, OP_CREATE_RESOURCE, OP_DISPLAY_INFO, OP_FLUSH, OP_HEALTHCHECK,
    OP_MODE_LIST, OP_QUERY_CAPS, OP_SET_SCANOUT, OP_TRANSFER_TO_HOST,
};
use crate::server::{handlers, respond};

const SERVICE_INBOX: u64 = 0;

pub fn run(driver: Driver) -> ! {
    let mut rx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    let mut tx = vec![0u8; HDR_LEN + IPC_PAYLOAD_MAX];
    loop_once(driver, &mut rx, &mut tx);
}

fn loop_once(driver: Driver, rx: &mut [u8], tx: &mut [u8]) -> ! {
    loop {
        let mut sender_pid = 0u32;
        let n = mk_ipc_recv_from(SERVICE_INBOX, rx.as_mut_ptr(), rx.len(), 0, &mut sender_pid);
        if n <= 0 || sender_pid == 0 {
            continue;
        }
        let Some((req, body)) = parse(&rx[..n as usize]) else { continue };
        dispatch(&driver, sender_pid, req, body, tx);
    }
}

fn dispatch(
    driver: &Driver,
    sender_pid: u32,
    req: crate::protocol::Request,
    body: &[u8],
    tx: &mut [u8],
) {
    match req.op {
        OP_HEALTHCHECK if body.is_empty() => handlers::health::handle(sender_pid, &req, tx),
        OP_CONTROLLER_INFO if body.is_empty() => {
            handlers::controller::handle(driver, sender_pid, &req, tx)
        }
        OP_DISPLAY_INFO if body.is_empty() => {
            handlers::display::handle(driver, sender_pid, &req, tx)
        }
        OP_CONTROLQ_STATE if body.is_empty() => {
            handlers::controlq::handle(driver, sender_pid, &req, tx)
        }
        OP_QUERY_CAPS if body.is_empty() => {
            handlers::query_caps::handle(driver, sender_pid, &req, tx)
        }
        OP_MODE_LIST if body.is_empty() => {
            handlers::mode_list::handle(driver, sender_pid, &req, tx)
        }
        OP_CREATE_RESOURCE => handlers::create_resource::handle(driver, sender_pid, &req, body, tx),
        OP_ATTACH_BACKING => handlers::attach_backing::handle(driver, sender_pid, &req, body, tx),
        OP_TRANSFER_TO_HOST => {
            handlers::transfer_to_host::handle(driver, sender_pid, &req, body, tx)
        }
        OP_SET_SCANOUT => handlers::set_scanout::handle(driver, sender_pid, &req, body, tx),
        OP_FLUSH => handlers::flush::handle(driver, sender_pid, &req, body, tx),
        _ if body.is_empty() => {
            let _ = respond::status(sender_pid, &req, E_BAD_OP, tx);
        }
        _ => {
            let _ = respond::status(sender_pid, &req, E_INVAL, tx);
        }
    }
}
