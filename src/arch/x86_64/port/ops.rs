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

use super::stats::PORT_STATS;
use super::types::PortValue;

// SAFETY: Port 0x80 is the POST code port, safe for delays
#[inline]
pub unsafe fn io_delay() {
    PORT_STATS.io_delays.fetch_add(1, Ordering::Relaxed);
    core::arch::asm!(
        "out 0x80, al",
        in("al") 0u8,
        options(nomem, nostack, preserves_flags)
    );
}

// SAFETY: See io_delay
#[inline]
pub unsafe fn io_delay_n(count: u32) {
    for _ in 0..count {
        io_delay();
    }
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(1, Ordering::Relaxed);
    u8::read_from_port(port)
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(2, Ordering::Relaxed);
    u16::read_from_port(port)
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(4, Ordering::Relaxed);
    u32::read_from_port(port)
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(1, Ordering::Relaxed);
    u8::write_to_port(port, value);
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(2, Ordering::Relaxed);
    u16::write_to_port(port, value);
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(4, Ordering::Relaxed);
    u32::write_to_port(port, value);
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn inb_p(port: u16) -> u8 {
    let value = inb(port);
    io_delay();
    value
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outb_p(port: u16, value: u8) {
    outb(port, value);
    io_delay();
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn inw_p(port: u16) -> u16 {
    let value = inw(port);
    io_delay();
    value
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outw_p(port: u16, value: u16) {
    outw(port, value);
    io_delay();
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn insb(port: u16, buffer: &mut [u8]) {
    PORT_STATS.string_read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    u8::read_string_from_port(port, buffer);
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn insw(port: u16, buffer: &mut [u16]) {
    PORT_STATS.string_read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add((buffer.len() * 2) as u64, Ordering::Relaxed);
    u16::read_string_from_port(port, buffer);
}

// SAFETY: Reading from I/O ports can have side effects on hardware state
#[inline]
pub unsafe fn insl(port: u16, buffer: &mut [u32]) {
    PORT_STATS.string_read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add((buffer.len() * 4) as u64, Ordering::Relaxed);
    u32::read_string_from_port(port, buffer);
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outsb(port: u16, buffer: &[u8]) {
    PORT_STATS.string_write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(buffer.len() as u64, Ordering::Relaxed);
    u8::write_string_to_port(port, buffer);
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outsw(port: u16, buffer: &[u16]) {
    PORT_STATS.string_write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add((buffer.len() * 2) as u64, Ordering::Relaxed);
    u16::write_string_to_port(port, buffer);
}

// SAFETY: Writing to I/O ports can affect hardware state
#[inline]
pub unsafe fn outsl(port: u16, buffer: &[u32]) {
    PORT_STATS.string_write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add((buffer.len() * 4) as u64, Ordering::Relaxed);
    u32::write_string_to_port(port, buffer);
}
