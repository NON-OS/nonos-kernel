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
use crate::arch::x86_64::pci::constants::{config, MAX_BARS};
use crate::arch::x86_64::pci::error::{PciError, PciResult};
use crate::arch::x86_64::pci::types::{BarType, PciBar};
use super::device::PciDevice;

impl PciDevice {
    pub fn get_bar(&self, bar_index: u8) -> PciResult<PciBar> {
        if bar_index >= MAX_BARS {
            return Err(PciError::InvalidBarIndex { index: bar_index });
        }

        let bar_offset = config::BAR0 + (bar_index as u16 * 4);
        let bar_value = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);

        if bar_value == 0 {
            return Err(PciError::BarNotImplemented { bar: bar_index });
        }

        let is_io = (bar_value & 1) != 0;

        if is_io {
            let base_addr = (bar_value & !0x3) as u64;

            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, 0xFFFFFFFF);
            let size_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, bar_value);

            let size = (!(size_mask & !0x3)).wrapping_add(1) as u64 & 0xFFFF;

            Ok(PciBar {
                base_addr, size, bar_type: BarType::Io, prefetchable: false, is_64bit: false,
            })
        } else {
            let prefetchable = (bar_value & 0x08) != 0;
            let bar_type_bits = (bar_value >> 1) & 0x03;
            let is_64bit = bar_type_bits == 2;

            let base_addr = if is_64bit {
                if bar_index >= 5 {
                    return Err(PciError::Bar64BitSpansTwo { bar: bar_index });
                }
                let high = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset + 4);
                ((high as u64) << 32) | ((bar_value & !0xF) as u64)
            } else {
                (bar_value & !0xF) as u64
            };

            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, 0xFFFFFFFF);
            let size_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, bar_value);

            let size = if is_64bit {
                pci_config_write_dword(self.bus, self.slot, self.function, bar_offset + 4, 0xFFFFFFFF);
                let high_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset + 4);
                let high_orig = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset + 4);
                pci_config_write_dword(self.bus, self.slot, self.function, bar_offset + 4, high_orig);

                let full_mask = ((high_mask as u64) << 32) | ((size_mask & !0xF) as u64);
                (!full_mask).wrapping_add(1)
            } else {
                (!(size_mask & !0xF)).wrapping_add(1) as u64
            };

            Ok(PciBar { base_addr, size, bar_type: BarType::Memory, prefetchable, is_64bit })
        }
    }
}
