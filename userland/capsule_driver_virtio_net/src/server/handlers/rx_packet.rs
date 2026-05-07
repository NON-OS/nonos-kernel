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

//! `OP_RX_PACKET`. Non-blocking. Returns one ready frame from the
//! used ring or `E_AGAIN` if the queue is empty. Reply body is
//! `[u32 length][frame bytes...]` so the kernel client can
//! validate length without trusting the trailing payload size.

use nonos_libc::mk_ipc_send;

use crate::protocol::{
    encode_response_header, write_status, KERNEL_REPLY_ENDPOINT, RX_PAYLOAD_PREFIX_LEN, Request,
    RESP_HDR_LEN, STATUS_LEN, E_AGAIN,
};
use crate::rx::take_one;
use crate::server::error::reply_with_status;
use crate::setup::Driver;

pub fn handle(driver: &mut Driver, req: &Request, tx: &mut [u8]) {
    // SAFETY: server loop is single-threaded; the frame bytes
    // are copied into `tx` before any further mutation of the
    // underlying RX pool.
    let frame = unsafe { take_one(&mut driver.rx) };
    let frame = match frame {
        Some(f) => f,
        None => {
            reply_with_status(tx, req, E_AGAIN);
            return;
        }
    };
    let len = frame.bytes.len();
    let body_len = RX_PAYLOAD_PREFIX_LEN + len;
    let payload_len = STATUS_LEN as u32 + body_len as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let prefix = (len as u32).to_le_bytes();
    tx[RESP_HDR_LEN + STATUS_LEN..RESP_HDR_LEN + STATUS_LEN + RX_PAYLOAD_PREFIX_LEN]
        .copy_from_slice(&prefix);
    tx[RESP_HDR_LEN + STATUS_LEN + RX_PAYLOAD_PREFIX_LEN
        ..RESP_HDR_LEN + STATUS_LEN + body_len]
        .copy_from_slice(frame.bytes);
    let _ = mk_ipc_send(
        KERNEL_REPLY_ENDPOINT,
        tx.as_ptr(),
        RESP_HDR_LEN + STATUS_LEN + body_len,
    );
}
