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

pub(crate) fn test_bar_offset_calculation() -> TestResult {
    if constants::bar_offset(0) != constants::CFG_BAR0 {
        return TestResult::Fail;
    }
    if constants::bar_offset(1) != constants::CFG_BAR1 {
        return TestResult::Fail;
    }
    if constants::bar_offset(5) != constants::CFG_BAR5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pci_bar_properties() -> TestResult {
    let mem32 = types::PciBar::Memory32 {
        address: crate::memory::addr::PhysAddr::new(0xF000_0000),
        size: 0x1000,
        prefetchable: true,
    };

    if !mem32.is_memory() {
        return TestResult::Fail;
    }
    if mem32.is_io() {
        return TestResult::Fail;
    }
    if mem32.is_64bit() {
        return TestResult::Fail;
    }
    if !mem32.is_prefetchable() {
        return TestResult::Fail;
    }
    if !mem32.is_present() {
        return TestResult::Fail;
    }
    if mem32.size() != 0x1000 {
        return TestResult::Fail;
    }
    if mem32.address() != Some(crate::memory::addr::PhysAddr::new(0xF000_0000)) {
        return TestResult::Fail;
    }

    let mem64 = types::PciBar::Memory64 {
        address: crate::memory::addr::PhysAddr::new(0x1_0000_0000),
        size: 0x100000,
        prefetchable: false,
    };

    if !mem64.is_64bit() {
        return TestResult::Fail;
    }
    if mem64.is_prefetchable() {
        return TestResult::Fail;
    }

    let io = types::PciBar::Io { port: 0x1000, size: 0x100 };
    if !io.is_io() {
        return TestResult::Fail;
    }
    if io.is_memory() {
        return TestResult::Fail;
    }
    if io.port() != Some(0x1000) {
        return TestResult::Fail;
    }

    let none = types::PciBar::NotPresent;
    if none.is_present() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bar_alignment_calculation() -> TestResult {
    if bar::calculate_bar_alignment(0) != 0 {
        return TestResult::Fail;
    }
    if bar::calculate_bar_alignment(1) != 1 {
        return TestResult::Fail;
    }
    if bar::calculate_bar_alignment(100) != 128 {
        return TestResult::Fail;
    }
    if bar::calculate_bar_alignment(256) != 256 {
        return TestResult::Fail;
    }
    if bar::calculate_bar_alignment(1000) != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bar_type_identification() -> TestResult {
    let mem32 = types::PciBar::Memory32 {
        address: crate::memory::addr::PhysAddr::new(0xF000_0000),
        size: 0x1000,
        prefetchable: false,
    };
    if bar::bar_type(&mem32) != error::BarType::Memory32 {
        return TestResult::Fail;
    }

    let mem64 = types::PciBar::Memory64 {
        address: crate::memory::addr::PhysAddr::new(0x1_0000_0000),
        size: 0x1000,
        prefetchable: false,
    };
    if bar::bar_type(&mem64) != error::BarType::Memory64 {
        return TestResult::Fail;
    }

    let io = types::PciBar::Io { port: 0x1000, size: 0x100 };
    if bar::bar_type(&io) != error::BarType::Io {
        return TestResult::Fail;
    }

    let none = types::PciBar::NotPresent;
    if bar::bar_type(&none) != error::BarType::NotPresent {
        return TestResult::Fail;
    }
    TestResult::Pass
}
