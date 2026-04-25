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

use super::types::{PCI_CONFIG_ADDRESS, PCI_CONFIG_DATA};
use crate::sys::io::{inl, outl};

pub(super) fn pci_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

pub fn pci_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = pci_address(bus, device, function, offset);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

pub fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let value = pci_read32(bus, device, function, offset & 0xFC);
    ((value >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

pub fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let value = pci_read32(bus, device, function, offset & 0xFC);
    ((value >> ((offset & 3) * 8)) & 0xFF) as u8
}

pub fn pci_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = pci_address(bus, device, function, offset);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, value);
    }
}

pub fn pci_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let old = pci_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    let new_value = (old & !(0xFFFFu32 << shift)) | ((value as u32) << shift);
    pci_write32(bus, device, function, offset & 0xFC, new_value);
}

pub fn pci_write8(bus: u8, device: u8, function: u8, offset: u8, value: u8) {
    let old = pci_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 3) * 8;
    let new_value = (old & !(0xFFu32 << shift)) | ((value as u32) << shift);
    pci_write32(bus, device, function, offset & 0xFC, new_value);
}
