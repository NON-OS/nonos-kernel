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

// Capability-level MSI-X bit-flip helpers. Table-entry programming
// (message address / data / mask-bit per vector) lives at the higher
// level in `drivers::pci::msi::msix`, which requires BAR MMIO mapping
// via `MmioManager::map_region` and a runtime LAPIC dest_id from
// `apic::ops::id`. Neither of those is wired through this file; the
// previous `configure_msix(table_index, addr, data)` claimed table
// programming but only flipped the cap-level enable bit, so it has
// been removed. Callers needing table programming must go through the
// driver-layer MSI-X path.

use super::device_struct::PciDevice;
use crate::arch::x86_64::pci::config::{pci_config_read_word, pci_config_write_word};
use crate::arch::x86_64::pci::constants::capability;
use crate::arch::x86_64::pci::error::{PciError, PciResult};

impl PciDevice {
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
