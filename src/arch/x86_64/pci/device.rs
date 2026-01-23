// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::config::{
    pci_config_read_byte, pci_config_read_dword, pci_config_read_word, pci_config_write_dword,
    pci_config_write_word,
};
use super::constants::{capability, command, config, status, MAX_BARS};
use super::error::{PciError, PciResult};
use super::stats::ERROR_COUNTER;
use super::types::{BarType, PciBar, PciCapability};

#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision_id: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub multifunction: bool,
}

impl PciDevice {
    pub fn new(bus: u8, slot: u8, function: u8) -> Option<Self> {
        let vendor_id = pci_config_read_word(bus, slot, function, config::VENDOR_ID);

        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = pci_config_read_word(bus, slot, function, config::DEVICE_ID);
        let class_code = pci_config_read_byte(bus, slot, function, config::CLASS_CODE);
        let subclass = pci_config_read_byte(bus, slot, function, config::SUBCLASS);
        let prog_if = pci_config_read_byte(bus, slot, function, config::PROG_IF);
        let revision_id = pci_config_read_byte(bus, slot, function, config::REVISION_ID);
        let raw_header_type = pci_config_read_byte(bus, slot, function, config::HEADER_TYPE);
        let header_type = raw_header_type & 0x7F;
        let multifunction = (raw_header_type & 0x80) != 0;
        let interrupt_line = pci_config_read_byte(bus, slot, function, config::INTERRUPT_LINE);
        let interrupt_pin = pci_config_read_byte(bus, slot, function, config::INTERRUPT_PIN);
        let subsystem_vendor_id = pci_config_read_word(bus, slot, function, config::SUBSYSTEM_VENDOR_ID);
        let subsystem_id = pci_config_read_word(bus, slot, function, config::SUBSYSTEM_ID);

        Some(PciDevice {
            bus, slot, function, vendor_id, device_id, class_code, subclass, prog_if,
            revision_id, header_type, interrupt_line, interrupt_pin, subsystem_vendor_id,
            subsystem_id, multifunction,
        })
    }

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

    pub fn enable_bus_mastering(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::BUS_MASTER;
        self.write_command(cmd);

        if (self.read_command() & command::BUS_MASTER) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::BusMasteringDisabled);
        }
        Ok(())
    }

    pub fn enable_memory_space(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::MEMORY_SPACE;
        self.write_command(cmd);

        if (self.read_command() & command::MEMORY_SPACE) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::MemorySpaceDisabled);
        }
        Ok(())
    }

    pub fn enable_io_space(&self) -> PciResult<()> {
        let mut cmd = self.read_command();
        cmd |= command::IO_SPACE;
        self.write_command(cmd);

        if (self.read_command() & command::IO_SPACE) == 0 {
            ERROR_COUNTER.fetch_add(1, Ordering::Relaxed);
            return Err(PciError::IoSpaceDisabled);
        }
        Ok(())
    }

    pub fn disable_interrupts(&self) {
        let mut cmd = self.read_command();
        cmd |= command::INTERRUPT_DISABLE;
        self.write_command(cmd);
    }

    pub fn enable_interrupts(&self) {
        let mut cmd = self.read_command();
        cmd &= !command::INTERRUPT_DISABLE;
        self.write_command(cmd);
    }

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
