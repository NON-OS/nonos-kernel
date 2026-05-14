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

// `driver.xhci0` service loop: drain event ring, ack IRQ, block
// on IPC, dispatch. P0 ops carry no payload.

use alloc::vec;

use nonos_libc::mk_ipc_recv;

use crate::controller::{ack_irq, drain_events};
use crate::debug::marker;
use crate::protocol::{
    decode_request, E_INVAL, HDR_LEN, MAX_PORTS_REPORTED, OP_CONTROLLER_STATUS, OP_HEALTHCHECK,
    OP_PORT_STATUS, PORT_ENTRY_BYTES, PORT_STATUS_HEADER_BYTES, RESP_HDR_LEN, STATUS_LEN,
};
use crate::server::context::Context;
use crate::server::error::{reply_decode_failed, reply_with_status};
use crate::server::handlers;
use crate::setup::Driver;

/// Worst-case reply size: a full PORT_STATUS payload.
const TX_LEN: usize =
    RESP_HDR_LEN + STATUS_LEN + PORT_STATUS_HEADER_BYTES + MAX_PORTS_REPORTED * PORT_ENTRY_BYTES;

pub fn run(driver: Driver) -> ! {
    let mut rx = vec![0u8; HDR_LEN];
    let mut tx = vec![0u8; TX_LEN];
    let mut ctx = Context::new(driver);

    marker(b"endpoint driver.xhci0 ready");

    loop {
        let batch = drain_events(ctx.driver.layout.primary_intr_base, &mut ctx.driver.event_ring);
        ctx.events_drained_total = ctx.events_drained_total.wrapping_add(batch.count as u64);
        ack_irq(ctx.driver.layout.primary_intr_base, ctx.driver.handles.irq_grant_id());

        let n = mk_ipc_recv(0, rx.as_mut_ptr(), HDR_LEN, 0);
        if n <= 0 {
            continue;
        }
        let req = match decode_request(&rx[..n as usize]) {
            Some(r) => r,
            None => {
                reply_decode_failed(&mut tx, E_INVAL);
                continue;
            }
        };
        if req.payload_len != 0 {
            reply_with_status(&mut tx, &req, E_INVAL);
            continue;
        }
        match req.op {
            OP_HEALTHCHECK => handlers::health::handle(&req, &mut tx),
            OP_CONTROLLER_STATUS => handlers::controller_status::handle(&ctx, &req, &mut tx),
            OP_PORT_STATUS => handlers::port_status::handle(&ctx, &req, &mut tx),
            _ => reply_with_status(&mut tx, &req, E_INVAL),
        }
    }
}
