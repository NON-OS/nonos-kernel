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

//! `OP_LINK_STATUS`. Returns one byte: 1 = link up, 0 = link
//! down. Without `VIRTIO_NET_F_STATUS` the spec leaves the status
//! word undefined, so the capsule treats the link as
//! unconditionally up in that case — a deterministic answer
//! beats reading garbage.

use nonos_libc::mk_ipc_send;

use crate::constants::{LEG_NET_STATUS_OFFSET, VIRTIO_NET_S_LINK_UP};
use crate::protocol::{
    encode_response_header, write_status, KERNEL_REPLY_ENDPOINT, LINK_STATUS_PAYLOAD_LEN, Request,
    RESP_HDR_LEN, STATUS_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let up = if driver.status_supported {
        let s = unsafe { driver.regs.r16(LEG_NET_STATUS_OFFSET) };
        (s & VIRTIO_NET_S_LINK_UP) != 0
    } else {
        true
    };
    let payload_len = STATUS_LEN as u32 + LINK_STATUS_PAYLOAD_LEN as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    tx[RESP_HDR_LEN + STATUS_LEN] = if up { 1 } else { 0 };
    let _ = mk_ipc_send(
        KERNEL_REPLY_ENDPOINT,
        tx.as_ptr(),
        RESP_HDR_LEN + STATUS_LEN + LINK_STATUS_PAYLOAD_LEN,
    );
}
