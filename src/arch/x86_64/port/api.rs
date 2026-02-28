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

use super::stats::{PortStats, PORT_STATS};
use super::types::{Port, PortReadOnly, PortValue, PortWriteOnly};

#[inline]
pub const fn port<T: PortValue>(port: u16) -> Port<T> {
    Port::new(port)
}

#[inline]
pub const fn port_read_only<T: PortValue>(port: u16) -> PortReadOnly<T> {
    PortReadOnly::new(port)
}

#[inline]
pub const fn port_write_only<T: PortValue>(port: u16) -> PortWriteOnly<T> {
    PortWriteOnly::new(port)
}

pub fn get_stats() -> &'static PortStats {
    &PORT_STATS
}
