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

//! `OP_LINK_STATUS`. Reads the live STATUS.LU bit and returns one
//! byte: `1 = link up`, `0 = link down`. The status register is
//! sampled on every call so a topology change between two probes
//! is observable to the kernel client.

use nonos_libc::mk_ipc_send;

use crate::constants::regs::REG_STATUS;
use crate::constants::status::STATUS_LU;
use crate::protocol::{
    encode_response_header, write_status, Request, KERNEL_REPLY_ENDPOINT, LINK_STATUS_PAYLOAD_LEN,
    RESP_HDR_LEN, STATUS_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    // SAFETY: eK@nonos.systems — `driver.regs` carries the broker
    // MmioMap base for BAR0; `REG_STATUS` is a 4-byte-aligned offset
    // documented in the 8254x manual.
    let s = unsafe { driver.regs.r32(REG_STATUS) };
    let up = (s & STATUS_LU) != 0;
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
