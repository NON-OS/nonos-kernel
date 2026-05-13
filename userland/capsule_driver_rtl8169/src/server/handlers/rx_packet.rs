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

use nonos_libc::mk_ipc_send;

use crate::protocol::{
    encode_response_header, write_status, Request, E_AGAIN, E_IO, KERNEL_REPLY_ENDPOINT,
    RESP_HDR_LEN, RX_PAYLOAD_PREFIX_LEN, STATUS_LEN,
};
use crate::rx::recv_one;
use crate::server::error::reply_with_status;
use crate::setup::Driver;

pub fn handle(driver: &mut Driver, req: &Request, tx: &mut [u8]) {
    let body_off = RESP_HDR_LEN + STATUS_LEN + RX_PAYLOAD_PREFIX_LEN;
    let frame_len = match recv_one(driver, &mut tx[body_off..]) {
        Ok(Some(n)) => n,
        Ok(None) => {
            reply_with_status(tx, req, E_AGAIN);
            return;
        }
        Err(_) => {
            reply_with_status(tx, req, E_IO);
            return;
        }
    };
    let body_len = RX_PAYLOAD_PREFIX_LEN + frame_len;
    encode_response_header(tx, req, STATUS_LEN as u32 + body_len as u32);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    tx[RESP_HDR_LEN + STATUS_LEN..body_off].copy_from_slice(&(frame_len as u32).to_le_bytes());
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), body_off + frame_len);
}
