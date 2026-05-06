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

//! Common payload helpers the per-op handlers share. Keeps the
//! handler files focused on their own op shape rather than on
//! envelope and status bookkeeping.

use nonos_libc::mk_ipc_send;

use crate::protocol::{
    encode_response_header, write_status, Request, KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN, STATUS_LEN,
};

/// Send a success response carrying a body. The body is written
/// immediately after the four-byte status field; the caller has
/// already serialised the body into the slice that follows
/// `RESP_HDR_LEN + STATUS_LEN` in `tx`.
pub(crate) fn reply_with_body(tx: &mut [u8], req: &Request, body_len: usize) {
    let payload_len = STATUS_LEN as u32 + body_len as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let total = RESP_HDR_LEN + STATUS_LEN + body_len;
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), total);
}

/// Slice of the transmit buffer the per-op body should be written
/// into. Returns `None` when the requested body length would not
/// fit; the handler then sends an `E_MSGSIZE` error reply instead
/// of truncating.
pub(crate) fn body_slot(tx: &mut [u8], body_len: usize) -> Option<&mut [u8]> {
    let start = RESP_HDR_LEN + STATUS_LEN;
    let end = start.checked_add(body_len)?;
    tx.get_mut(start..end)
}
