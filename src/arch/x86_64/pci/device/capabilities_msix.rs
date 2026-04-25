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
use crate::arch::x86_64::pci::constants::capability;
use crate::arch::x86_64::pci::error::{PciError, PciResult};

impl PciDevice {
    pub fn configure_msix(&self, table_index: u16, _addr: u64, _data: u32) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX).ok_or(PciError::MsixNotSupported)?;
        let msg_ctrl =
            pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let table_size = (msg_ctrl & 0x7FF) + 1;
        if table_index >= table_size {
            return Err(PciError::InvalidConfigAccess {
                bus: self.bus,
                slot: self.slot,
                function: self.function,
                offset: table_index,
            });
        }
        let new_ctrl = msg_ctrl | 0x8000;
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);
        Ok(())
    }

    pub fn enable_msix(&self) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX).ok_or(PciError::MsixNotSupported)?;
        let msg_ctrl =
            pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        pci_config_write_word(
            self.bus,
            self.slot,
            self.function,
            (msix_cap + 2) as u16,
            msg_ctrl | 0x8000,
        );
        Ok(())
    }

    pub fn disable_msix(&self) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX).ok_or(PciError::MsixNotSupported)?;
        let msg_ctrl =
            pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        pci_config_write_word(
            self.bus,
            self.slot,
            self.function,
            (msix_cap + 2) as u16,
            msg_ctrl & !0x8000,
        );
        Ok(())
    }

    pub fn has_msix(&self) -> bool {
        self.find_capability(capability::MSIX).is_some()
    }
    pub fn has_msi(&self) -> bool {
        self.find_capability(capability::MSI).is_some()
    }
}
