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

use super::config::{pci_read16, pci_read32, pci_read8};
use super::types::PciDevice;

pub(super) fn device_exists(bus: u8, device: u8, function: u8) -> bool {
    pci_read16(bus, device, function, 0x00) != 0xFFFF
}

pub(super) fn read_device(bus: u8, device: u8, function: u8) -> PciDevice {
    PciDevice {
        bus,
        device,
        function,
        vendor_id: pci_read16(bus, device, function, 0x00),
        device_id: pci_read16(bus, device, function, 0x02),
        class: pci_read8(bus, device, function, 0x0B),
        subclass: pci_read8(bus, device, function, 0x0A),
        prog_if: pci_read8(bus, device, function, 0x09),
        header_type: pci_read8(bus, device, function, 0x0E),
        bar0: pci_read32(bus, device, function, 0x10),
        bar1: pci_read32(bus, device, function, 0x14),
        bar2: pci_read32(bus, device, function, 0x18),
        bar3: pci_read32(bus, device, function, 0x1C),
        bar4: pci_read32(bus, device, function, 0x20),
        bar5: pci_read32(bus, device, function, 0x24),
        irq_line: pci_read8(bus, device, function, 0x3C),
        irq_pin: pci_read8(bus, device, function, 0x3D),
    }
}
