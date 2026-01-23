// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
    0x8000_0000
        | ((bus as u32) << 16)
        | ((slot as u32 & 0x1F) << 11)
        | ((function as u32 & 0x07) << 8)
        | ((offset as u32) & 0xFC)
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

#[inline]
pub fn pci_config_read_word(bus: u8, slot: u8, function: u8, offset: u16) -> u16 {
    let dword = pci_config_read_dword(bus, slot, function, offset & 0xFFFC);
    let shift = ((offset & 2) * 8) as u32;
    ((dword >> shift) & 0xFFFF) as u16
}

#[inline]
pub fn pci_config_write_word(bus: u8, slot: u8, function: u8, offset: u16, value: u16) {
    let aligned_offset = offset & 0xFFFC;
    let mut dword = pci_config_read_dword(bus, slot, function, aligned_offset);
    let shift = ((offset & 2) * 8) as u32;
    dword = (dword & !(0xFFFF << shift)) | ((value as u32) << shift);
    pci_config_write_dword(bus, slot, function, aligned_offset, dword);
}

#[inline]
pub fn pci_config_read_byte(bus: u8, slot: u8, function: u8, offset: u16) -> u8 {
    let dword = pci_config_read_dword(bus, slot, function, offset & 0xFFFC);
    let shift = ((offset & 3) * 8) as u32;
    ((dword >> shift) & 0xFF) as u8
}

#[inline]
pub fn pci_config_write_byte(bus: u8, slot: u8, function: u8, offset: u16, value: u8) {
    let aligned_offset = offset & 0xFFFC;
    let mut dword = pci_config_read_dword(bus, slot, function, aligned_offset);
    let shift = ((offset & 3) * 8) as u32;
    dword = (dword & !(0xFF << shift)) | ((value as u32) << shift);
    pci_config_write_dword(bus, slot, function, aligned_offset, dword);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_config_address() {
        let addr = make_config_address(0, 0, 0, 0);
        assert_eq!(addr, 0x8000_0000);

        let addr = make_config_address(1, 2, 3, 0x10);
        assert_eq!(addr, 0x8001_1310);
    }
}
