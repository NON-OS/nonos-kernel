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

#[inline]
pub unsafe fn io_delay() {
    PORT_STATS.io_delays.fetch_add(1, Ordering::Relaxed);
    core::arch::asm!("out 0x80, al", in("al") 0u8, options(nomem, nostack, preserves_flags));
}

#[inline]
pub unsafe fn io_delay_n(count: u32) { for _ in 0..count { io_delay(); } }

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(1, Ordering::Relaxed);
    u8::read_from_port(port)
}

#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(2, Ordering::Relaxed);
    u16::read_from_port(port)
}

#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_read.fetch_add(4, Ordering::Relaxed);
    u32::read_from_port(port)
}

#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(1, Ordering::Relaxed);
    u8::write_to_port(port, value);
}

#[inline]
pub unsafe fn outw(port: u16, value: u16) {
    PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(2, Ordering::Relaxed);
    u16::write_to_port(port, value);
}

#[inline]
pub unsafe fn outl(port: u16, value: u32) {
    PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
    PORT_STATS.bytes_written.fetch_add(4, Ordering::Relaxed);
    u32::write_to_port(port, value);
}
