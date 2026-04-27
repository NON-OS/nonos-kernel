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
use crate::arch::x86_64::pci::error::{PciError, PciResult};
use crate::arch::x86_64::pci::types::{BarType, PciBar};

pub fn parse_mem_bar(
    bus: u8,
    slot: u8,
    func: u8,
    bar_offset: u16,
    bar_value: u32,
    bar_index: u8,
) -> PciResult<PciBar> {
    let prefetchable = (bar_value & 0x08) != 0;
    let bar_type_bits = (bar_value >> 1) & 0x03;
    let is_64bit = bar_type_bits == 2;
    let base_addr = if is_64bit {
        if bar_index >= 5 {
            return Err(PciError::Bar64BitSpansTwo { bar: bar_index });
        }
        let high = pci_config_read_dword(bus, slot, func, bar_offset + 4);
        ((high as u64) << 32) | ((bar_value & !0xF) as u64)
    } else {
        (bar_value & !0xF) as u64
    };
    pci_config_write_dword(bus, slot, func, bar_offset, 0xFFFFFFFF);
    let size_mask = pci_config_read_dword(bus, slot, func, bar_offset);
    pci_config_write_dword(bus, slot, func, bar_offset, bar_value);
    let size = if is_64bit {
        pci_config_write_dword(bus, slot, func, bar_offset + 4, 0xFFFFFFFF);
        let high_mask = pci_config_read_dword(bus, slot, func, bar_offset + 4);
        let high_orig = pci_config_read_dword(bus, slot, func, bar_offset + 4);
        pci_config_write_dword(bus, slot, func, bar_offset + 4, high_orig);
        let full_mask = ((high_mask as u64) << 32) | ((size_mask & !0xF) as u64);
        (!full_mask).wrapping_add(1)
    } else {
        (!(size_mask & !0xF)).wrapping_add(1) as u64
    };
    Ok(PciBar { base_addr, size, bar_type: BarType::Memory, prefetchable, is_64bit })
}
