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

use super::bars_io::parse_io_bar;
use super::bars_mem::parse_mem_bar;
use super::device_struct::PciDevice;
use crate::arch::x86_64::pci::config::pci_config_read_dword;
use crate::arch::x86_64::pci::constants::{config, MAX_BARS};
use crate::arch::x86_64::pci::error::{PciError, PciResult};
use crate::arch::x86_64::pci::types::PciBar;

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
            Ok(parse_io_bar(self.bus, self.slot, self.function, bar_offset, bar_value))
        } else {
            parse_mem_bar(self.bus, self.slot, self.function, bar_offset, bar_value, bar_index)
        }
    }
}
