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

use core::arch::asm;
use super::super::constants::{REG_DATA, REG_LSR, LSR_DATA_READY, LSR_TX_EMPTY, TX_TIMEOUT};
use super::super::error::SerialError;

#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") value,
        options(nomem, nostack, preserves_flags)
    );
    value
}

#[inline]
pub fn io_wait() {
    // SAFETY: Port 0x80 is used for POST codes, safe for delays
    unsafe { outb(0x80, 0); }
}

#[inline]
pub fn read_reg(base: u16, reg: u16) -> u8 {
    // SAFETY: Caller ensures valid port address
    unsafe { inb(base + reg) }
}

#[inline]
pub fn write_reg(base: u16, reg: u16, value: u8) {
    // SAFETY: Caller ensures valid port address
    unsafe { outb(base + reg, value); }
}

#[inline]
pub fn is_tx_empty(base: u16) -> bool {
    read_reg(base, REG_LSR) & LSR_TX_EMPTY != 0
}

#[inline]
pub fn is_data_ready(base: u16) -> bool {
    read_reg(base, REG_LSR) & LSR_DATA_READY != 0
}

pub fn write_byte_timeout(base: u16, byte: u8) -> Result<(), SerialError> {
    let mut timeout = TX_TIMEOUT;

    while !is_tx_empty(base) {
        if timeout == 0 {
            return Err(SerialError::TransmitTimeout);
        }
        timeout -= 1;
        // SAFETY: pause is always safe on x86_64
        unsafe { asm!("pause", options(nomem, nostack)); }
    }

    write_reg(base, REG_DATA, byte);
    Ok(())
}

pub fn read_byte_direct(base: u16) -> Option<u8> {
    if is_data_ready(base) {
        Some(read_reg(base, REG_DATA))
    } else {
        None
    }
}
