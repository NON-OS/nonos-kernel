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

use core::sync::atomic::Ordering;
use super::constants::{ports, Register};
use super::state::STATS_WRITES;

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Reading from I/O port. Caller must ensure port is valid.
    unsafe {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags, nomem)
        );
        value
    }
}

#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Writing to I/O port. Caller must ensure port is valid.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("al") value,
            in("dx") port,
            options(nostack, preserves_flags, nomem)
        );
    }
}

#[inline]
pub fn cmos_read(register: u8) -> u8 {
    // SAFETY: CMOS ports are standard x86 hardware.
    unsafe {
        outb(ports::CMOS_ADDR, register | 0x80);
        inb(0x80);
        inb(ports::CMOS_DATA)
    }
}

#[inline]
pub fn cmos_write(register: u8, value: u8) {
    // SAFETY: CMOS ports are standard x86 hardware.
    unsafe {
        outb(ports::CMOS_ADDR, register | 0x80);
        inb(0x80);
        outb(ports::CMOS_DATA, value);
    }
}

pub fn read_register(register: Register) -> u8 {
    cmos_read(register as u8)
}

pub fn write_register(register: Register, value: u8) {
    cmos_write(register as u8, value);
    STATS_WRITES.fetch_add(1, Ordering::Relaxed);
}

pub fn read_cmos(address: u8) -> u8 {
    if address > 0x7F {
        return 0;
    }
    cmos_read(address)
}

pub fn write_cmos(address: u8, value: u8) {
    if address > 0x7F {
        return;
    }
    cmos_write(address, value);
    STATS_WRITES.fetch_add(1, Ordering::Relaxed);
}
