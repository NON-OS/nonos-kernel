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
use crate::test::framework::TestResult;

pub(crate) fn test_class_name_lookup() -> TestResult {
    if constants::class_name(constants::CLASS_MASS_STORAGE) != "Mass Storage" {
        return TestResult::Fail;
    }
    if constants::class_name(constants::CLASS_NETWORK) != "Network" {
        return TestResult::Fail;
    }
    if constants::class_name(constants::CLASS_DISPLAY) != "Display" {
        return TestResult::Fail;
    }
    if constants::class_name(constants::CLASS_SERIAL_BUS) != "Serial Bus" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capability_name_lookup() -> TestResult {
    if constants::capability_name(constants::CAP_ID_MSI) != "MSI" {
        return TestResult::Fail;
    }
    if constants::capability_name(constants::CAP_ID_MSIX) != "MSI-X" {
        return TestResult::Fail;
    }
    if constants::capability_name(constants::CAP_ID_PM) != "Power Management" {
        return TestResult::Fail;
    }
    if constants::capability_name(constants::CAP_ID_PCIE) != "PCI Express" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pcie_link_speed_string() -> TestResult {
    if constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_2_5GT) != "2.5 GT/s (Gen1)" {
        return TestResult::Fail;
    }
    if constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_8GT) != "8 GT/s (Gen3)" {
        return TestResult::Fail;
    }
    if constants::pcie_link_speed_str(constants::PCIE_LINK_SPEED_32GT) != "32 GT/s (Gen5)" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_command_register_bits() -> TestResult {
    if constants::CMD_IO_SPACE != 1 << 0 {
        return TestResult::Fail;
    }
    if constants::CMD_MEMORY_SPACE != 1 << 1 {
        return TestResult::Fail;
    }
    if constants::CMD_BUS_MASTER != 1 << 2 {
        return TestResult::Fail;
    }
    if constants::CMD_INTERRUPT_DISABLE != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_status_register_bits() -> TestResult {
    if constants::STS_CAPABILITIES_LIST != 1 << 4 {
        return TestResult::Fail;
    }
    if constants::STS_66MHZ_CAPABLE != 1 << 5 {
        return TestResult::Fail;
    }
    if constants::STS_DETECTED_PARITY_ERROR != 1 << 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vendor_ids() -> TestResult {
    if constants::VENDOR_INTEL != 0x8086 {
        return TestResult::Fail;
    }
    if constants::VENDOR_AMD != 0x1022 {
        return TestResult::Fail;
    }
    if constants::VENDOR_NVIDIA != 0x10DE {
        return TestResult::Fail;
    }
    if constants::VENDOR_VIRTIO != 0x1AF4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
