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

//! `driver.virtio_rng` service loop. One in-flight request at a
//! time; bounded receive and transmit buffers; deterministic error
//! returns for malformed envelopes and unknown ops.

use alloc::vec;

use nonos_libc::mk_ipc_recv;

use crate::protocol::{
    decode_request, E_INVAL, HDR_LEN, MAX_FILL_BYTES, OP_FILL_RANDOM, OP_HEALTHCHECK,
    RESP_HDR_LEN, STATUS_LEN,
};
use crate::server::error::{reply_decode_failed, reply_with_status};
use crate::server::handlers;
use crate::setup::Driver;

const RX_BUF_LEN: usize = HDR_LEN;
const TX_BUF_LEN: usize = RESP_HDR_LEN + STATUS_LEN + MAX_FILL_BYTES as usize;

pub fn run(driver: &mut Driver) -> ! {
    let mut rx = vec![0u8; RX_BUF_LEN];
    let mut tx = vec![0u8; TX_BUF_LEN];
    loop {
        let n = mk_ipc_recv(0, rx.as_mut_ptr(), RX_BUF_LEN, 0);
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
        match req.op {
            OP_FILL_RANDOM => handlers::fill::handle(driver, &req, &mut tx),
            OP_HEALTHCHECK => handlers::health::handle(&req, &mut tx),
            _ => reply_with_status(&mut tx, &req, E_INVAL),
        }
    }
}
