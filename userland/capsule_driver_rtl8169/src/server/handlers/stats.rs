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

use crate::constants::queue::{RX_DESC_COUNT, TX_DESC_COUNT};
use crate::constants::regs::{
    REG_CMD, REG_IMR, REG_ISR, REG_PHY_STATUS, REG_RMS, REG_RX_CONFIG, REG_TX_CONFIG,
};
use crate::protocol::{
    encode_response_header, write_status, Request, KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
    STATS_PAYLOAD_LEN, STATUS_LEN,
};
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let payload_len = STATUS_LEN as u32 + STATS_PAYLOAD_LEN as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + STATUS_LEN;
    for v in live_regs(driver) {
        put32(tx, &mut o, v);
    }
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + payload_len as usize);
}

fn live_regs(driver: &Driver) -> [u32; 12] {
    unsafe {
        [
            driver.regs.r8(REG_CMD) as u32,
            driver.regs.r8(REG_PHY_STATUS) as u32,
            driver.regs.r16(REG_ISR) as u32,
            driver.regs.r16(REG_IMR) as u32,
            driver.regs.r32(REG_RX_CONFIG),
            driver.regs.r32(REG_TX_CONFIG),
            driver.regs.r16(REG_RMS) as u32,
            driver.rx.cur as u32,
            driver.tx.cur as u32,
            RX_DESC_COUNT as u32,
            TX_DESC_COUNT as u32,
            0,
        ]
    }
}

fn put32(tx: &mut [u8], o: &mut usize, v: u32) {
    tx[*o..*o + 4].copy_from_slice(&v.to_le_bytes());
    *o += 4;
}
