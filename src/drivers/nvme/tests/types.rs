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

use crate::drivers::nvme::{constants, types};
use crate::test::framework::TestResult;

pub(crate) fn test_controller_capabilities() -> TestResult {
    let cap: u64 = 0x0014_0000_0020_00FF;
    let caps = types::ControllerCapabilities::from_register(cap);

    if caps.max_queue_entries != 256 {
        return TestResult::Fail;
    }
    if caps.timeout_500ms_units != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_controller_version() -> TestResult {
    let vs: u32 = 0x0001_0400;
    let version = types::ControllerVersion::from_register(vs);

    if version.major != 1 {
        return TestResult::Fail;
    }
    if version.minor != 4 {
        return TestResult::Fail;
    }
    if version.tertiary != 0 {
        return TestResult::Fail;
    }
    if !version.is_at_least(1, 3) {
        return TestResult::Fail;
    }
    if !version.is_at_least(1, 4) {
        return TestResult::Fail;
    }
    if version.is_at_least(1, 5) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lba_format() -> TestResult {
    let dword: u32 = 0x0009_0000;
    let format = types::LbaFormat::from_dword(dword);

    if format.lba_data_size_shift != 9 {
        return TestResult::Fail;
    }
    if format.lba_size() != 512 {
        return TestResult::Fail;
    }
    if format.metadata_size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lba_format_4k() -> TestResult {
    let dword: u32 = 0x000C_0000;
    let format = types::LbaFormat::from_dword(dword);

    if format.lba_data_size_shift != 12 {
        return TestResult::Fail;
    }
    if format.lba_size() != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dsm_range() -> TestResult {
    let range = types::DsmRange::new(0x1000, 8, constants::DSM_ATTR_DEALLOCATE);

    if range.starting_lba != 0x1000 {
        return TestResult::Fail;
    }
    if range.lba_count != 8 {
        return TestResult::Fail;
    }
    if range.context_attributes != constants::DSM_ATTR_DEALLOCATE {
        return TestResult::Fail;
    }
    TestResult::Pass
}
