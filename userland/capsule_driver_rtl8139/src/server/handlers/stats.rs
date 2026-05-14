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

use crate::constants::regs::{
    REG_CAPR, REG_CMD, REG_ISR, REG_MSR, REG_RCR, REG_TCR, REG_TXSTATUS0,
};
use crate::protocol::{
    encode_response_header, write_status, Request, E_IO, KERNEL_REPLY_ENDPOINT, RESP_HDR_LEN,
    STATS_PAYLOAD_LEN, STATUS_LEN,
};
use crate::server::error::reply_with_status;
use crate::setup::Driver;

pub fn handle(driver: &Driver, req: &Request, tx: &mut [u8]) {
    let regs = match live_regs(driver) {
        Ok(v) => v,
        Err(()) => {
            reply_with_status(tx, req, E_IO);
            return;
        }
    };
    let payload_len = STATUS_LEN as u32 + STATS_PAYLOAD_LEN as u32;
    encode_response_header(tx, req, payload_len);
    write_status(&mut tx[RESP_HDR_LEN..], 0);
    let mut o = RESP_HDR_LEN + STATUS_LEN;
    for v in regs {
        put32(tx, &mut o, v);
    }
    let _ = mk_ipc_send(KERNEL_REPLY_ENDPOINT, tx.as_ptr(), RESP_HDR_LEN + payload_len as usize);
}

fn live_regs(driver: &Driver) -> Result<[u32; 12], ()> {
    Ok([
        driver.pio.r8(REG_CMD).map_err(|_| ())? as u32,
        driver.pio.r8(REG_MSR).map_err(|_| ())? as u32,
        driver.pio.r16(REG_ISR).map_err(|_| ())? as u32,
        driver.pio.r32(REG_RCR).map_err(|_| ())?,
        driver.pio.r32(REG_TCR).map_err(|_| ())?,
        driver.pio.r16(REG_CAPR).map_err(|_| ())? as u32,
        driver.pio.r32(REG_TXSTATUS0).map_err(|_| ())?,
        driver.pio.r32(REG_TXSTATUS0 + 4).map_err(|_| ())?,
        driver.pio.r32(REG_TXSTATUS0 + 8).map_err(|_| ())?,
        driver.pio.r32(REG_TXSTATUS0 + 12).map_err(|_| ())?,
        driver.rx_offset as u32,
        driver.tx_cur as u32,
    ])
}

fn put32(tx: &mut [u8], o: &mut usize, v: u32) {
    tx[*o..*o + 4].copy_from_slice(&v.to_le_bytes());
    *o += 4;
}
