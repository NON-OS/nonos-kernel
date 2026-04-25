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

use super::device_struct::PciDevice;
use crate::arch::x86_64::pci::config::{pci_config_read_word, pci_config_write_word};
use crate::arch::x86_64::pci::constants::config;

impl PciDevice {
    #[inline]
    pub fn bdf(&self) -> u16 {
        ((self.bus as u16) << 8) | ((self.slot as u16) << 3) | (self.function as u16)
    }

    #[inline]
    pub fn read_command(&self) -> u16 {
        pci_config_read_word(self.bus, self.slot, self.function, config::COMMAND)
    }

    #[inline]
    pub fn write_command(&self, value: u16) {
        pci_config_write_word(self.bus, self.slot, self.function, config::COMMAND, value);
    }

    #[inline]
    pub fn read_status(&self) -> u16 {
        pci_config_read_word(self.bus, self.slot, self.function, config::STATUS)
    }
}
