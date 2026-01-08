// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::constants::*;

#[inline(always)]
pub unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller ensures valid port.
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[inline(always)]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller ensures valid port.
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags));
    v
}

#[inline]
pub unsafe fn crt_write(reg: u8, val: u8) {
    // SAFETY: Caller ensures valid register.
    outb(CRT_INDEX_PORT, reg);
    outb(CRT_DATA_PORT, val);
}

#[inline]
pub unsafe fn crt_read(reg: u8) -> u8 {
    // SAFETY: Caller ensures valid register.
    outb(CRT_INDEX_PORT, reg);
    inb(CRT_DATA_PORT)
}

pub fn set_cursor_position(pos: u16) {
    // SAFETY: Writing to VGA CRT controller ports.
    unsafe {
        outb(CRT_INDEX_PORT, CRT_CURSOR_LOC_LOW);
        outb(CRT_DATA_PORT, (pos & 0xFF) as u8);
        outb(CRT_INDEX_PORT, CRT_CURSOR_LOC_HIGH);
        outb(CRT_DATA_PORT, ((pos >> 8) & 0xFF) as u8);
    }
}

pub fn get_cursor_position() -> u16 {
    // SAFETY: Reading from VGA CRT controller ports.
    unsafe {
        outb(CRT_INDEX_PORT, CRT_CURSOR_LOC_HIGH);
        let high = inb(CRT_DATA_PORT) as u16;
        outb(CRT_INDEX_PORT, CRT_CURSOR_LOC_LOW);
        let low = inb(CRT_DATA_PORT) as u16;
        (high << 8) | low
    }
}

pub fn enable_cursor(scanline_start: u8, scanline_end: u8) {
    // SAFETY: Writing to VGA CRT controller ports.
    unsafe {
        outb(CRT_INDEX_PORT, CRT_CURSOR_START);
        let cur_start = inb(CRT_DATA_PORT);
        outb(CRT_DATA_PORT, (cur_start & 0xC0) | (scanline_start & CURSOR_START_MASK));
        outb(CRT_INDEX_PORT, CRT_CURSOR_END);
        let cur_end = inb(CRT_DATA_PORT);
        outb(CRT_DATA_PORT, (cur_end & 0xE0) | (scanline_end & CURSOR_END_MASK));
    }
}

pub fn disable_cursor() {
    // SAFETY: Writing to VGA CRT controller ports.
    unsafe {
        outb(CRT_INDEX_PORT, CRT_CURSOR_START);
        let cur_start = inb(CRT_DATA_PORT);
        outb(CRT_DATA_PORT, cur_start | CURSOR_DISABLE_BIT);
    }
}

pub fn is_cursor_enabled() -> bool {
    // SAFETY: Reading from VGA CRT controller ports.
    unsafe {
        outb(CRT_INDEX_PORT, CRT_CURSOR_START);
        let cur_start = inb(CRT_DATA_PORT);
        (cur_start & CURSOR_DISABLE_BIT) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_position_encoding() {
        let row = 10;
        let col = 40;
        let pos = (row * VGA_WIDTH + col) as u16;
        assert_eq!(pos, 840);
    }
}
