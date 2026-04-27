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

use crate::drivers::xhci::stats;
use crate::test::framework::TestResult;

pub(crate) fn test_stats_increment() -> TestResult {
    let stats = stats::XhciStatistics::new();

    stats.inc_interrupts();
    stats.inc_commands();
    stats.inc_transfers();
    stats.add_bytes(1024);

    let snapshot = stats.snapshot();
    if snapshot.interrupts != 1 {
        return TestResult::Fail;
    }
    if snapshot.commands_completed != 1 {
        return TestResult::Fail;
    }
    if snapshot.transfers != 1 {
        return TestResult::Fail;
    }
    if snapshot.bytes_transferred != 1024 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_stats_total_errors() -> TestResult {
    let stats = stats::XhciStatistics::new();

    stats.inc_timeouts();
    stats.inc_stalls();

    if stats.total_errors() != 2 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_stats_error_rate() -> TestResult {
    let mut snapshot = stats::XhciStats::new();
    snapshot.transfers = 90;
    snapshot.errors = 10;

    let rate = snapshot.error_rate();
    if (rate - 10.0).abs() >= 0.01 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_controller_health() -> TestResult {
    let mut snapshot = stats::XhciStats::new();
    snapshot.transfers = 100;
    snapshot.errors = 0;

    if stats::ControllerHealth::from_stats(&snapshot) != stats::ControllerHealth::Healthy {
        return TestResult::Fail;
    }

    snapshot.errors = 5;
    if stats::ControllerHealth::from_stats(&snapshot) != stats::ControllerHealth::Warning {
        return TestResult::Fail;
    }

    snapshot.errors = 20;
    if stats::ControllerHealth::from_stats(&snapshot) != stats::ControllerHealth::Critical {
        return TestResult::Fail;
    }

    TestResult::Pass
}
