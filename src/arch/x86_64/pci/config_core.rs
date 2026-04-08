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
use super::constants::{PCI_CONFIG_ADDRESS, PCI_CONFIG_DATA};
use super::io;
use super::stats::{CONFIG_READ_COUNTER, CONFIG_WRITE_COUNTER};

#[inline]
fn make_config_address(bus: u8, slot: u8, function: u8, offset: u16) -> u32 {
    0x8000_0000 | ((bus as u32) << 16) | ((slot as u32 & 0x1F) << 11)
        | ((function as u32 & 0x07) << 8) | ((offset as u32) & 0xFC)
}

#[inline]
pub fn pci_config_read_dword(bus: u8, slot: u8, function: u8, offset: u16) -> u32 {
    CONFIG_READ_COUNTER.fetch_add(1, Ordering::Relaxed);
    let address = make_config_address(bus, slot, function, offset);
    io::write_u32(PCI_CONFIG_ADDRESS, address);
    io::read_u32(PCI_CONFIG_DATA)
}

#[inline]
pub fn pci_config_write_dword(bus: u8, slot: u8, function: u8, offset: u16, value: u32) {
    CONFIG_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let address = make_config_address(bus, slot, function, offset);
    io::write_u32(PCI_CONFIG_ADDRESS, address);
    io::write_u32(PCI_CONFIG_DATA, value);
}
