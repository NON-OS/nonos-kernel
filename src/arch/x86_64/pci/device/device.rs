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

use crate::arch::x86_64::pci::config::{
    pci_config_read_byte, pci_config_read_word, pci_config_write_word,
};
use crate::arch::x86_64::pci::constants::config;

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
}
