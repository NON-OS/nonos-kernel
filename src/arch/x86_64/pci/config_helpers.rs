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

use super::config_core::{pci_config_read_dword, pci_config_write_dword};

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
