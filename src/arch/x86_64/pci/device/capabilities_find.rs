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
use crate::arch::x86_64::pci::config::pci_config_read_byte;
use crate::arch::x86_64::pci::constants::{config, status};
use crate::arch::x86_64::pci::types::PciCapability;
use alloc::vec::Vec;

impl PciDevice {
    pub fn find_capability(&self, cap_id: u8) -> Option<u8> {
        let stat = self.read_status();
        if (stat & status::CAPABILITIES_LIST) == 0 {
            return None;
        }
        let mut cap_ptr =
            pci_config_read_byte(self.bus, self.slot, self.function, config::CAPABILITIES_PTR)
                & 0xFC;
        for _ in 0..48 {
            if cap_ptr == 0 {
                break;
            }
            let id = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr as u16);
            if id == cap_id {
                return Some(cap_ptr);
            }
            cap_ptr =
                pci_config_read_byte(self.bus, self.slot, self.function, (cap_ptr + 1) as u16)
                    & 0xFC;
        }
        None
    }

    pub fn get_capabilities(&self) -> Vec<PciCapability> {
        let mut caps = Vec::new();
        let stat = self.read_status();
        if (stat & status::CAPABILITIES_LIST) == 0 {
            return caps;
        }
        let mut cap_ptr =
            pci_config_read_byte(self.bus, self.slot, self.function, config::CAPABILITIES_PTR)
                & 0xFC;
        for _ in 0..48 {
            if cap_ptr == 0 {
                break;
            }
            let id = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr as u16);
            let next =
                pci_config_read_byte(self.bus, self.slot, self.function, (cap_ptr + 1) as u16)
                    & 0xFC;
            caps.push(PciCapability { id, offset: cap_ptr, next });
            cap_ptr = next;
        }
        caps
    }
}
