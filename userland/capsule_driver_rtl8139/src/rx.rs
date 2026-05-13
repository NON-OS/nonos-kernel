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

use core::sync::atomic::{compiler_fence, Ordering};

use nonos_libc::mk_irq_ack;

use crate::constants::dma::RX_BUF_DATA_BYTES;
use crate::constants::regs::{
    CMD_RX_BUF_EMPTY, ISR_ENABLED, ISR_RX_ERR, ISR_RX_FIFO_OVERFLOW, ISR_RX_OVERFLOW, REG_CAPR,
    REG_CMD, REG_ISR, RX_STATUS_OK,
};
use crate::constants::MAX_ETHERNET_FRAME;
use crate::setup::Driver;

pub fn recv_one(driver: &mut Driver, out: &mut [u8]) -> Result<Option<usize>, &'static str> {
    let isr = driver.pio.r16(REG_ISR)?;
    if isr != 0 {
        driver.pio.w16(REG_ISR, isr & ISR_ENABLED)?;
    }
    if (isr & (ISR_RX_ERR | ISR_RX_OVERFLOW | ISR_RX_FIFO_OVERFLOW)) != 0 {
        let _ = mk_irq_ack(driver.irq_grant);
        return Err("rtl8139 rx interrupt error");
    }
    if (driver.pio.r8(REG_CMD)? & CMD_RX_BUF_EMPTY) != 0 {
        let _ = mk_irq_ack(driver.irq_grant);
        return Ok(None);
    }
    read_frame(driver, out)
}

fn read_frame(driver: &mut Driver, out: &mut [u8]) -> Result<Option<usize>, &'static str> {
    compiler_fence(Ordering::Acquire);
    let base = driver.rx_user_va;
    let off = driver.rx_offset;
    let status = ring_u16(base, off);
    let raw_len = ring_u16(base, off + 2) as usize;
    if (status & RX_STATUS_OK) == 0 || raw_len <= 4 {
        let _ = mk_irq_ack(driver.irq_grant);
        return Err("rtl8139 rx descriptor error");
    }
    let frame_len = raw_len - 4;
    if frame_len > MAX_ETHERNET_FRAME || frame_len > out.len() {
        let _ = mk_irq_ack(driver.irq_grant);
        return Err("rtl8139 rx frame too large");
    }
    copy_ring(base, off + 4, out, frame_len);
    advance(driver, raw_len)?;
    let _ = mk_irq_ack(driver.irq_grant);
    Ok(Some(frame_len))
}

fn advance(driver: &mut Driver, raw_len: usize) -> Result<(), &'static str> {
    let next = (driver.rx_offset + raw_len + 4 + 3) & !3;
    driver.rx_offset = next % RX_BUF_DATA_BYTES;
    let capr = (driver.rx_offset + RX_BUF_DATA_BYTES - 16) % RX_BUF_DATA_BYTES;
    driver.pio.w16(REG_CAPR, capr as u16)
}

fn ring_u16(base: u64, off: usize) -> u16 {
    let lo = ring_u8(base, off) as u16;
    let hi = ring_u8(base, off + 1) as u16;
    lo | (hi << 8)
}

fn ring_u8(base: u64, off: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base + (off % RX_BUF_DATA_BYTES) as u64) as *const u8) }
}

fn copy_ring(base: u64, start: usize, out: &mut [u8], len: usize) {
    for (i, byte) in out.iter_mut().take(len).enumerate() {
        *byte = ring_u8(base, start + i);
    }
}
