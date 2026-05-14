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

//! `OP_FILL_RANDOM` handler. Bounds the requested length, runs one
//! virtqueue round trip, copies the device's bytes into the
//! response buffer, and emits the response.

use nonos_libc::mk_ipc_send;

use crate::fill::fill;
use crate::protocol::{
    encode_response_header, write_status, Request, E_IO, E_MSGSIZE, KERNEL_REPLY_ENDPOINT,
    MAX_FILL_BYTES, RESP_HDR_LEN, STATUS_LEN,
};
use crate::server::error::reply_with_status;
use crate::setup::Driver;

pub fn handle(driver: &mut Driver, req: &Request, tx: &mut [u8]) {
    let want = req.payload_len;
    if want == 0 || want > MAX_FILL_BYTES {
        reply_with_status(tx, req, E_MSGSIZE);
        return;
    }
    let n = match fill(driver.regs, &mut driver.queue, driver.irq_grant) {
        Ok(n) => n,
        Err(_) => {
            reply_with_status(tx, req, E_IO);
            return;
        }
    };
    let take = core::cmp::min(want, n);
    let payload_len = STATUS_LEN as u32 + take;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    // SAFETY: the buffer belongs to the capsule's DMA grant; the
    // server loop is single-threaded so no concurrent device write
    // is in flight while the response is being copied.
    let bytes = unsafe { driver.queue.buffer(take) };
    let body = &mut tx[RESP_HDR_LEN + STATUS_LEN..RESP_HDR_LEN + STATUS_LEN + take as usize];
    body.copy_from_slice(&bytes[..take as usize]);
    let _ =
        mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + STATUS_LEN + take as usize);
}
