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

use crate::arch::x86_64::port::stats::PORT_STATS;
use super::value::PortValue;

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
