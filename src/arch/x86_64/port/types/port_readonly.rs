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

use super::value::PortValue;
use super::port_rw::Port;

#[derive(Debug, Clone, Copy)]
pub struct PortReadOnly<T: PortValue> {
    port: Port<T>,
}

impl<T: PortValue> PortReadOnly<T> {
    #[inline]
    pub const fn new(port: u16) -> Self { Self { port: Port::new(port) } }

    #[inline]
    pub const fn port(&self) -> u16 { self.port.port() }

    #[inline]
    pub unsafe fn read(&self) -> T { self.port.read() }

    #[inline]
    pub unsafe fn read_string(&self, buffer: &mut [T]) { self.port.read_string(buffer); }
}
