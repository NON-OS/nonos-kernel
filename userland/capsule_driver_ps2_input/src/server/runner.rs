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

//! `driver.ps2_kbd0` service loop. One in-flight request at a
//! time. Receive buffer carries the 20-byte envelope only (no
//! request payloads on this driver); transmit buffer is sized for
//! the largest reply, which is a full poll batch.

use alloc::vec;

use nonos_libc::mk_ipc_recv;

use crate::debug::marker;
use crate::protocol::{
    decode_request, EVENT_WIRE_LEN, E_INVAL, HDR_LEN, MAX_POLL_EVENTS, OP_GET_STATE,
    OP_HEALTHCHECK, OP_POLL_EVENTS, POLL_PAYLOAD_PREFIX_LEN, RESP_HDR_LEN, STATE_PAYLOAD_LEN,
    STATUS_LEN,
};
use crate::server::context::Context;
use crate::server::error::{reply_decode_failed, reply_with_status};
use crate::server::handlers;
use crate::setup::Driver;

pub fn run(driver: Driver) -> ! {
    let rx_len = HDR_LEN;
    let poll_tx_len = RESP_HDR_LEN + POLL_PAYLOAD_PREFIX_LEN + MAX_POLL_EVENTS * EVENT_WIRE_LEN;
    let state_tx_len = RESP_HDR_LEN + STATUS_LEN + STATE_PAYLOAD_LEN;
    let tx_len = core::cmp::max(poll_tx_len, state_tx_len);

    let mut rx = vec![0u8; rx_len];
    let mut tx = vec![0u8; tx_len];
    let mut ctx = Context::new(driver);

    marker(b"endpoint driver.ps2_kbd0 ready");

    loop {
        let n = mk_ipc_recv(0, rx.as_mut_ptr(), rx_len, 0);
        if n <= 0 {
            continue;
        }
        let len = n as usize;
        let req = match decode_request(&rx[..len]) {
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
            OP_POLL_EVENTS => handlers::poll::handle(&mut ctx, &req, &mut tx),
            OP_GET_STATE => handlers::state::handle(&mut ctx, &req, &mut tx),
            _ => reply_with_status(&mut tx, &req, E_INVAL),
        }
    }
}
