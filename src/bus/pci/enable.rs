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

use super::config::{pci_read16, pci_write16};

pub fn enable_bus_master(bus: u8, device: u8, function: u8) {
    let cmd = pci_read16(bus, device, function, 0x04);
    pci_write16(bus, device, function, 0x04, cmd | 0x04);
}

pub fn enable_memory_space(bus: u8, device: u8, function: u8) {
    let cmd = pci_read16(bus, device, function, 0x04);
    pci_write16(bus, device, function, 0x04, cmd | 0x02);
}

pub fn enable_io_space(bus: u8, device: u8, function: u8) {
    let cmd = pci_read16(bus, device, function, 0x04);
    pci_write16(bus, device, function, 0x04, cmd | 0x01);
}

pub fn get_bar_address(bar: u32) -> Option<u64> {
    if bar == 0 {
        return None;
    }
    if bar & 0x01 != 0 {
        Some((bar & 0xFFFF_FFFC) as u64)
    } else {
        let bar_type = (bar >> 1) & 0x03;
        match bar_type {
            0x00 => Some((bar & 0xFFFF_FFF0) as u64),
            0x02 => Some((bar & 0xFFFF_FFF0) as u64),
            _ => None,
        }
    }
}
