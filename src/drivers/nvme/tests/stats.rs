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

use crate::drivers::nvme::stats;
use crate::test::framework::TestResult;

pub(crate) fn test_stats_atomic_operations() -> TestResult {
    let stats = stats::NvmeStats::new();

    stats.record_submit();
    stats.record_submit();
    stats.record_complete();
    stats.record_read(4096);
    stats.record_write(8192);
    stats.record_error();

    let snapshot = stats.snapshot();
    if snapshot.commands_submitted != 2 {
        return TestResult::Fail;
    }
    if snapshot.commands_completed != 1 {
        return TestResult::Fail;
    }
    if snapshot.read_commands != 1 {
        return TestResult::Fail;
    }
    if snapshot.write_commands != 1 {
        return TestResult::Fail;
    }
    if snapshot.bytes_read != 4096 {
        return TestResult::Fail;
    }
    if snapshot.bytes_written != 8192 {
        return TestResult::Fail;
    }
    if snapshot.errors != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_stats() -> TestResult {
    let stats = stats::SecurityStats::new();

    stats.record_rate_limit();
    stats.record_lba_validation_failure();
    stats.record_dma_validation_failure();
    stats.record_cq_corruption();

    let snapshot = stats.snapshot();
    if snapshot.rate_limit_hits != 1 {
        return TestResult::Fail;
    }
    if snapshot.lba_validation_failures != 1 {
        return TestResult::Fail;
    }
    if snapshot.dma_validation_failures != 1 {
        return TestResult::Fail;
    }
    if snapshot.cq_corruption_events != 1 {
        return TestResult::Fail;
    }
    if !snapshot.has_critical_events() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
