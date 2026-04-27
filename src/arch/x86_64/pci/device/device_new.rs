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
use crate::arch::x86_64::pci::config::{pci_config_read_byte, pci_config_read_word};
use crate::arch::x86_64::pci::constants::config;

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
        let raw_header = pci_config_read_byte(bus, slot, function, config::HEADER_TYPE);
        let header_type = raw_header & 0x7F;
        let multifunction = (raw_header & 0x80) != 0;
        let interrupt_line = pci_config_read_byte(bus, slot, function, config::INTERRUPT_LINE);
        let interrupt_pin = pci_config_read_byte(bus, slot, function, config::INTERRUPT_PIN);
        let subsystem_vendor_id =
            pci_config_read_word(bus, slot, function, config::SUBSYSTEM_VENDOR_ID);
        let subsystem_id = pci_config_read_word(bus, slot, function, config::SUBSYSTEM_ID);
        Some(PciDevice {
            bus,
            slot,
            function,
            vendor_id,
            device_id,
            class_code,
            subclass,
            prog_if,
            revision_id,
            header_type,
            interrupt_line,
            interrupt_pin,
            subsystem_vendor_id,
            subsystem_id,
            multifunction,
        })
    }
}
