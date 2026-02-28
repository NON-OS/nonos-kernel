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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::arch::x86_64::pci::config::{
    pci_config_read_byte, pci_config_read_word, pci_config_write_word,
};
use crate::arch::x86_64::pci::constants::{capability, config, status};
use crate::arch::x86_64::pci::error::{PciError, PciResult};
use crate::arch::x86_64::pci::stats::ERROR_COUNTER;
use crate::arch::x86_64::pci::types::PciCapability;
use super::device::PciDevice;

impl PciDevice {
    pub fn find_capability(&self, cap_id: u8) -> Option<u8> {
        let stat = self.read_status();
        if (stat & status::CAPABILITIES_LIST) == 0 {
            return None;
        }

        let mut cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, config::CAPABILITIES_PTR) & 0xFC;

        for _ in 0..48 {
            if cap_ptr == 0 {
                break;
            }

            let id = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr as u16);
            if id == cap_id {
                return Some(cap_ptr);
            }

            cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, (cap_ptr + 1) as u16) & 0xFC;
        }

        None
    }

    pub fn get_capabilities(&self) -> Vec<PciCapability> {
        let mut caps = Vec::new();
        let stat = self.read_status();

        if (stat & status::CAPABILITIES_LIST) == 0 {
            return caps;
        }

        let mut cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, config::CAPABILITIES_PTR) & 0xFC;

        for _ in 0..48 {
            if cap_ptr == 0 {
                break;
            }

            let id = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr as u16);
            let next = pci_config_read_byte(self.bus, self.slot, self.function, (cap_ptr + 1) as u16) & 0xFC;

            caps.push(PciCapability { id, offset: cap_ptr, next });
            cap_ptr = next;
        }

        caps
    }

    pub fn configure_msix(&self, table_index: u16, _addr: u64, _data: u32) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX).ok_or(PciError::MsixNotSupported)?;

        let msg_ctrl = pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let table_size = (msg_ctrl & 0x7FF) + 1;

        if table_index >= table_size {
            return Err(PciError::InvalidConfigAccess {
                bus: self.bus, slot: self.slot, function: self.function, offset: table_index,
            });
        }

        let new_ctrl = msg_ctrl | 0x8000;
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);

        Ok(())
    }

    pub fn enable_msix(&self) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX).ok_or(PciError::MsixNotSupported)?;
        let msg_ctrl = pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let new_ctrl = msg_ctrl | 0x8000;
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);
        Ok(())
    }

    pub fn disable_msix(&self) -> PciResult<()> {
        let msix_cap = self.find_capability(capability::MSIX).ok_or(PciError::MsixNotSupported)?;
        let msg_ctrl = pci_config_read_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16);
        let new_ctrl = msg_ctrl & !0x8000;
        pci_config_write_word(self.bus, self.slot, self.function, (msix_cap + 2) as u16, new_ctrl);
        Ok(())
    }

    pub fn has_msix(&self) -> bool {
        self.find_capability(capability::MSIX).is_some()
    }

    pub fn has_msi(&self) -> bool {
        self.find_capability(capability::MSI).is_some()
    }

    pub fn check_and_clear_errors(&self) -> Option<u16> {
        let stat = self.read_status();
        let error_bits = stat & (
            status::MASTER_DATA_PARITY_ERROR |
            status::SIGNALED_TARGET_ABORT |
            status::RECEIVED_TARGET_ABORT |
            status::RECEIVED_MASTER_ABORT |
            status::SIGNALED_SYSTEM_ERROR |
            status::DETECTED_PARITY_ERROR
        );

        if error_bits != 0 {
            pci_config_write_word(self.bus, self.slot, self.function, config::STATUS, error_bits);
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            Some(error_bits)
        } else {
            None
        }
    }
}
