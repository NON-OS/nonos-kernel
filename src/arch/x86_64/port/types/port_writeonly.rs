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

use super::port_rw::Port;
use super::value::PortValue;

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

    #[inline]
    pub unsafe fn write(&self, value: T) {
        self.port.write(value);
    }

    #[inline]
    pub unsafe fn write_string(&self, buffer: &[T]) {
        self.port.write_string(buffer);
    }
}
