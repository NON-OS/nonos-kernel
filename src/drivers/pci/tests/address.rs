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

pub(crate) fn test_pci_address_creation() -> TestResult {
    let addr = types::PciAddress::new(0, 1, 2);
    if addr.bus != 0 {
        return TestResult::Fail;
    }
    if addr.device != 1 {
        return TestResult::Fail;
    }
    if addr.function != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_bdf_conversion() -> TestResult {
    let addr = types::PciAddress::new(5, 10, 3);
    let bdf = addr.to_bdf();
    let restored = types::PciAddress::from_bdf(bdf);

    if restored.bus != addr.bus {
        return TestResult::Fail;
    }
    if restored.device != addr.device {
        return TestResult::Fail;
    }
    if restored.function != addr.function {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_address_display() -> TestResult {
    use core::fmt::Write;
    let addr = types::PciAddress::new(0x12, 0x0A, 0x03);
    let mut buf = [0u8; 32];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{}", addr);
    let display = writer.as_str();
    if display != "12:0a.3" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_config_address_calculation() -> TestResult {
    let addr = constants::pci_config_address(0, 0, 0, 0);
    if addr & (1 << 31) != 1 << 31 {
        return TestResult::Fail;
    }

    let addr = constants::pci_config_address(5, 10, 3, 0x10);
    let expected = (1u32 << 31) | (5u32 << 16) | (10u32 << 11) | (3u32 << 8) | 0x10;
    if addr != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}
