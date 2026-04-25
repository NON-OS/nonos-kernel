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

use super::ops_basic::{inb, inw, io_delay, outb, outw};

#[inline]
pub unsafe fn inb_p(port: u16) -> u8 {
    let value = inb(port);
    io_delay();
    value
}

#[inline]
pub unsafe fn outb_p(port: u16, value: u8) {
    outb(port, value);
    io_delay();
}

#[inline]
pub unsafe fn inw_p(port: u16) -> u16 {
    let value = inw(port);
    io_delay();
    value
}

#[inline]
pub unsafe fn outw_p(port: u16, value: u16) {
    outw(port, value);
    io_delay();
}
