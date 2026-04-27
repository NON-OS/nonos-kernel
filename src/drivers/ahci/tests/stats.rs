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

use crate::drivers::ahci::stats::AhciStats;
use crate::test::framework::TestResult;

pub(crate) fn test_stats_default_read_ops() -> TestResult {
    let stats = AhciStats::default();
    if stats.read_ops != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_write_ops() -> TestResult {
    let stats = AhciStats::default();
    if stats.write_ops != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_trim_ops() -> TestResult {
    let stats = AhciStats::default();
    if stats.trim_ops != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_errors() -> TestResult {
    let stats = AhciStats::default();
    if stats.errors != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_bytes_read() -> TestResult {
    let stats = AhciStats::default();
    if stats.bytes_read != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_bytes_written() -> TestResult {
    let stats = AhciStats::default();
    if stats.bytes_written != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_devices_count() -> TestResult {
    let stats = AhciStats::default();
    if stats.devices_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_port_resets() -> TestResult {
    let stats = AhciStats::default();
    if stats.port_resets != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_default_validation_failures() -> TestResult {
    let stats = AhciStats::default();
    if stats.validation_failures != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_copy() -> TestResult {
    let stats1 = AhciStats {
        read_ops: 100,
        write_ops: 50,
        trim_ops: 10,
        errors: 2,
        bytes_read: 1024000,
        bytes_written: 512000,
        devices_count: 2,
        port_resets: 1,
        validation_failures: 0,
    };

    let stats2 = stats1;
    if stats1.read_ops != stats2.read_ops {
        return TestResult::Fail;
    }
    if stats1.write_ops != stats2.write_ops {
        return TestResult::Fail;
    }
    if stats1.trim_ops != stats2.trim_ops {
        return TestResult::Fail;
    }
    if stats1.errors != stats2.errors {
        return TestResult::Fail;
    }
    if stats1.bytes_read != stats2.bytes_read {
        return TestResult::Fail;
    }
    if stats1.bytes_written != stats2.bytes_written {
        return TestResult::Fail;
    }
    if stats1.devices_count != stats2.devices_count {
        return TestResult::Fail;
    }
    if stats1.port_resets != stats2.port_resets {
        return TestResult::Fail;
    }
    if stats1.validation_failures != stats2.validation_failures {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_clone() -> TestResult {
    let stats1 = AhciStats {
        read_ops: 200,
        write_ops: 100,
        trim_ops: 20,
        errors: 5,
        bytes_read: 2048000,
        bytes_written: 1024000,
        devices_count: 4,
        port_resets: 2,
        validation_failures: 1,
    };

    let stats2 = stats1.clone();
    if stats1.read_ops != stats2.read_ops {
        return TestResult::Fail;
    }
    if stats1.bytes_read != stats2.bytes_read {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_debug() -> TestResult {
    let stats = AhciStats::default();
    let debug_str = format!("{:?}", stats);
    if !debug_str.contains("AhciStats") {
        return TestResult::Fail;
    }
    if !debug_str.contains("read_ops") {
        return TestResult::Fail;
    }
    if !debug_str.contains("write_ops") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_field_independence() -> TestResult {
    let stats = AhciStats {
        read_ops: 1,
        write_ops: 2,
        trim_ops: 3,
        errors: 4,
        bytes_read: 5,
        bytes_written: 6,
        devices_count: 7,
        port_resets: 8,
        validation_failures: 9,
    };

    if stats.read_ops != 1 {
        return TestResult::Fail;
    }
    if stats.write_ops != 2 {
        return TestResult::Fail;
    }
    if stats.trim_ops != 3 {
        return TestResult::Fail;
    }
    if stats.errors != 4 {
        return TestResult::Fail;
    }
    if stats.bytes_read != 5 {
        return TestResult::Fail;
    }
    if stats.bytes_written != 6 {
        return TestResult::Fail;
    }
    if stats.devices_count != 7 {
        return TestResult::Fail;
    }
    if stats.port_resets != 8 {
        return TestResult::Fail;
    }
    if stats.validation_failures != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_stats_large_values() -> TestResult {
    let stats = AhciStats {
        read_ops: u64::MAX,
        write_ops: u64::MAX,
        trim_ops: u64::MAX,
        errors: u64::MAX,
        bytes_read: u64::MAX,
        bytes_written: u64::MAX,
        devices_count: u32::MAX,
        port_resets: u64::MAX,
        validation_failures: u64::MAX,
    };

    if stats.read_ops != u64::MAX {
        return TestResult::Fail;
    }
    if stats.devices_count != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}
