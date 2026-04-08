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

use crate::arch::x86_64::pci::config::{pci_config_read_dword, pci_config_write_dword};
use crate::arch::x86_64::pci::types::{BarType, PciBar};

pub fn parse_io_bar(bus: u8, slot: u8, function: u8, bar_offset: u16, bar_value: u32) -> PciBar {
    let base_addr = (bar_value & !0x3) as u64;
    pci_config_write_dword(bus, slot, function, bar_offset, 0xFFFFFFFF);
    let size_mask = pci_config_read_dword(bus, slot, function, bar_offset);
    pci_config_write_dword(bus, slot, function, bar_offset, bar_value);
    let size = (!(size_mask & !0x3)).wrapping_add(1) as u64 & 0xFFFF;
    PciBar { base_addr, size, bar_type: BarType::Io, prefetchable: false, is_64bit: false }
}
