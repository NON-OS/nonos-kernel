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
//! RX ring (status DD set) or `E_AGAIN` if the ring is empty.
//! Reply body is `[u32 length][frame bytes...]` so the kernel
//! client can validate length without trusting the trailing
//! payload size. After a frame is copied out, RDT is bumped so
//! the device may refill the slot on its next pass.

use nonos_libc::mk_ipc_send;

use crate::constants::regs::REG_RDT;
use crate::protocol::{
    encode_response_header, write_status, Request, E_AGAIN, KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
    RX_PAYLOAD_PREFIX_LEN, STATUS_LEN,
};
use crate::server::error::reply_with_status;
use crate::setup::Driver;

pub fn handle(driver: &mut Driver, req: &Request, tx: &mut [u8]) {
    let (idx, len) = match driver.rx.consume() {
        Some(p) => p,
        None => {
            reply_with_status(tx, req, E_AGAIN);
            return;
        }
    };
    let body_len = RX_PAYLOAD_PREFIX_LEN + len as usize;
    let payload_len = STATUS_LEN as u32 + body_len as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let prefix = (len as u32).to_le_bytes();
    let prefix_off = RESP_HDR_LEN + STATUS_LEN;
    let body_off = prefix_off + RX_PAYLOAD_PREFIX_LEN;
    tx[prefix_off..body_off].copy_from_slice(&prefix);
    let src = driver.rx.buffer_va(idx) as *const u8;
    // SAFETY: eK@nonos.systems — `src` lies inside the RX buffer
    // pool's broker DMA grant (RX_BUFFER_LEN bytes per slot,
    // device-reported `len` capped by the descriptor format).
    unsafe {
        core::ptr::copy_nonoverlapping(src, tx[body_off..].as_mut_ptr(), len as usize);
    }
    // SAFETY: same MMIO grant invariants as the rest of `regs`.
    unsafe {
        driver.regs.w32(REG_RDT, idx as u32);
    }
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), prefix_off + body_len);
}
