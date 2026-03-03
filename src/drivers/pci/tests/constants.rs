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

use crate::drivers::pci::*;

#[test]
fn test_class_name_lookup() {
    assert_eq!(constants::class_name(constants::CLASS_MASS_STORAGE), "Mass Storage");
    assert_eq!(constants::class_name(constants::CLASS_NETWORK), "Network");
    assert_eq!(constants::class_name(constants::CLASS_DISPLAY), "Display");
    assert_eq!(constants::class_name(constants::CLASS_SERIAL_BUS), "Serial Bus");
}

#[test]
fn test_capability_name_lookup() {
    assert_eq!(constants::capability_name(constants::CAP_ID_MSI), "MSI");
    assert_eq!(constants::capability_name(constants::CAP_ID_MSIX), "MSI-X");
    assert_eq!(constants::capability_name(constants::CAP_ID_PM), "Power Management");
    assert_eq!(constants::capability_name(constants::CAP_ID_PCIE), "PCI Express");
}

#[test]
fn test_pcie_link_speed_string() {
    assert_eq!(constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_2_5GT), "2.5 GT/s (Gen1)");
    assert_eq!(constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_8GT), "8 GT/s (Gen3)");
    assert_eq!(constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_32GT), "32 GT/s (Gen5)");
}

#[test]
fn test_command_register_bits() {
    assert_eq!(constants::CMD_IO_SPACE, 1 << 0);
    assert_eq!(constants::CMD_MEMORY_SPACE, 1 << 1);
    assert_eq!(constants::CMD_BUS_MASTER, 1 << 2);
    assert_eq!(constants::CMD_INTERRUPT_DISABLE, 1 << 10);
}

#[test]
fn test_status_register_bits() {
    assert_eq!(constants::STS_CAPABILITIES_LIST, 1 << 4);
    assert_eq!(constants::STS_66MHZ_CAPABLE, 1 << 5);
    assert_eq!(constants::STS_DETECTED_PARITY_ERROR, 1 << 15);
}

#[test]
fn test_vendor_ids() {
    assert_eq!(constants::VENDOR_INTEL, 0x8086);
    assert_eq!(constants::VENDOR_AMD, 0x1022);
    assert_eq!(constants::VENDOR_NVIDIA, 0x10DE);
    assert_eq!(constants::VENDOR_VIRTIO, 0x1AF4);
}
