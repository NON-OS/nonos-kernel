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

use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use super::stats::PORT_STATS;

pub trait PortValue: Copy + Default {
    // SAFETY: Reading from I/O ports can have side effects on hardware
    unsafe fn read_from_port(port: u16) -> Self;

    // SAFETY: Writing to I/O ports can have side effects on hardware
    unsafe fn write_to_port(port: u16, value: Self);

    // SAFETY: Reading from I/O ports can have side effects on hardware
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]);

    // SAFETY: Writing to I/O ports can have side effects on hardware
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]);

    fn size() -> usize;
}

impl PortValue for u8 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insb",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsb",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize { 1 }
}

impl PortValue for u16 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u16;
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insw",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsw",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize { 2 }
}

impl PortValue for u32 {
    #[inline]
    unsafe fn read_from_port(port: u16) -> Self {
        let value: u32;
        core::arch::asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
        value
    }

    #[inline]
    unsafe fn write_to_port(port: u16, value: Self) {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn read_string_from_port(port: u16, buffer: &mut [Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep insd",
            in("dx") port,
            inout("rdi") buffer.as_mut_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    #[inline]
    unsafe fn write_string_to_port(port: u16, buffer: &[Self]) {
        if buffer.is_empty() {
            return;
        }
        core::arch::asm!(
            "rep outsd",
            in("dx") port,
            inout("rsi") buffer.as_ptr() => _,
            inout("rcx") buffer.len() => _,
            options(nostack, preserves_flags)
        );
    }

    fn size() -> usize { 4 }
}

#[derive(Debug, Clone, Copy)]
pub struct Port<T: PortValue> {
    port: u16,
    _marker: PhantomData<T>,
}

impl<T: PortValue> Port<T> {
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self { port, _marker: PhantomData }
    }

    #[inline]
    pub const fn port(&self) -> u16 {
        self.port
    }

    // SAFETY: Reading from I/O ports can have side effects on hardware state
    #[inline]
    pub unsafe fn read(&self) -> T {
        PORT_STATS.read_ops.fetch_add(1, Ordering::Relaxed);
        PORT_STATS.bytes_read.fetch_add(T::size() as u64, Ordering::Relaxed);
        T::read_from_port(self.port)
    }

    // SAFETY: Writing to I/O ports can affect hardware state
    #[inline]
    pub unsafe fn write(&self, value: T) {
        PORT_STATS.write_ops.fetch_add(1, Ordering::Relaxed);
        PORT_STATS.bytes_written.fetch_add(T::size() as u64, Ordering::Relaxed);
        T::write_to_port(self.port, value);
    }

    // SAFETY: Reading from I/O ports can have side effects on hardware state
    #[inline]
    pub unsafe fn read_string(&self, buffer: &mut [T]) {
        PORT_STATS.string_read_ops.fetch_add(1, Ordering::Relaxed);
        PORT_STATS.bytes_read.fetch_add((buffer.len() * T::size()) as u64, Ordering::Relaxed);
        T::read_string_from_port(self.port, buffer);
    }

    // SAFETY: Writing to I/O ports can affect hardware state
    #[inline]
    pub unsafe fn write_string(&self, buffer: &[T]) {
        PORT_STATS.string_write_ops.fetch_add(1, Ordering::Relaxed);
        PORT_STATS.bytes_written.fetch_add((buffer.len() * T::size()) as u64, Ordering::Relaxed);
        T::write_string_to_port(self.port, buffer);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PortReadOnly<T: PortValue> {
    port: Port<T>,
}

impl<T: PortValue> PortReadOnly<T> {
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self { port: Port::new(port) }
    }

    #[inline]
    pub const fn port(&self) -> u16 {
        self.port.port()
    }

    // SAFETY: Reading from I/O ports can have side effects on hardware state
    #[inline]
    pub unsafe fn read(&self) -> T {
        self.port.read()
    }

    // SAFETY: Reading from I/O ports can have side effects on hardware state
    #[inline]
    pub unsafe fn read_string(&self, buffer: &mut [T]) {
        self.port.read_string(buffer);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PortWriteOnly<T: PortValue> {
    port: Port<T>,
}

impl<T: PortValue> PortWriteOnly<T> {
    #[inline]
    pub const fn new(port: u16) -> Self {
        Self { port: Port::new(port) }
    }

    #[inline]
    pub const fn port(&self) -> u16 {
        self.port.port()
    }

    // SAFETY: Writing to I/O ports can affect hardware state
    #[inline]
    pub unsafe fn write(&self, value: T) {
        self.port.write(value);
    }

    // SAFETY: Writing to I/O ports can affect hardware state
    #[inline]
    pub unsafe fn write_string(&self, buffer: &[T]) {
        self.port.write_string(buffer);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    start: u16,
    count: u16,
}

impl PortRange {
    pub const fn new(start: u16, count: u16) -> Self {
        Self { start, count }
    }

    pub const fn start(&self) -> u16 {
        self.start
    }

    pub const fn count(&self) -> u16 {
        self.count
    }

    pub const fn end(&self) -> u16 {
        self.start.saturating_add(self.count)
    }

    pub const fn contains(&self, port: u16) -> bool {
        port >= self.start && port < self.end()
    }

    pub const fn overlaps(&self, other: &PortRange) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_value_sizes() {
        assert_eq!(u8::size(), 1);
        assert_eq!(u16::size(), 2);
        assert_eq!(u32::size(), 4);
    }

    #[test]
    fn test_port_creation() {
        let port8: Port<u8> = Port::new(0x3F8);
        let port16: Port<u16> = Port::new(0x1F0);
        let port32: Port<u32> = Port::new(0xCFC);

        assert_eq!(port8.port(), 0x3F8);
        assert_eq!(port16.port(), 0x1F0);
        assert_eq!(port32.port(), 0xCFC);
    }

    #[test]
    fn test_port_range() {
        let range = PortRange::new(0x100, 8);
        assert_eq!(range.start(), 0x100);
        assert_eq!(range.count(), 8);
        assert_eq!(range.end(), 0x108);

        assert!(range.contains(0x100));
        assert!(range.contains(0x107));
        assert!(!range.contains(0x108));
    }

    #[test]
    fn test_port_range_overlap() {
        let range1 = PortRange::new(0x100, 8);
        let range2 = PortRange::new(0x104, 8);
        let range3 = PortRange::new(0x108, 8);

        assert!(range1.overlaps(&range2));
        assert!(!range1.overlaps(&range3));
    }
}
