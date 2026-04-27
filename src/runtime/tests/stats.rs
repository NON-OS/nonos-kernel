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

use crate::runtime::*;
use crate::test::framework::TestResult;

pub(crate) fn test_snapshot_debug() -> TestResult {
    let snap = stats::Snapshot { starts: 1, stops: 2, restarts: 3, heartbeats: 4 };
    let debug_str = alloc::format!("{:?}", snap);
    if !debug_str.contains("Snapshot") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_clone() -> TestResult {
    let snap = stats::Snapshot { starts: 10, stops: 20, restarts: 30, heartbeats: 40 };
    let cloned = snap.clone();
    if snap.starts != cloned.starts {
        return TestResult::Fail;
    }
    if snap.stops != cloned.stops {
        return TestResult::Fail;
    }
    if snap.restarts != cloned.restarts {
        return TestResult::Fail;
    }
    if snap.heartbeats != cloned.heartbeats {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_starts_field() -> TestResult {
    let snap = stats::Snapshot { starts: 100, stops: 0, restarts: 0, heartbeats: 0 };
    if snap.starts != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_stops_field() -> TestResult {
    let snap = stats::Snapshot { starts: 0, stops: 200, restarts: 0, heartbeats: 0 };
    if snap.stops != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_restarts_field() -> TestResult {
    let snap = stats::Snapshot { starts: 0, stops: 0, restarts: 300, heartbeats: 0 };
    if snap.restarts != 300 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_heartbeats_field() -> TestResult {
    let snap = stats::Snapshot { starts: 0, stops: 0, restarts: 0, heartbeats: 400 };
    if snap.heartbeats != 400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_all_zeros() -> TestResult {
    let snap = stats::Snapshot { starts: 0, stops: 0, restarts: 0, heartbeats: 0 };
    if snap.starts != 0 {
        return TestResult::Fail;
    }
    if snap.stops != 0 {
        return TestResult::Fail;
    }
    if snap.restarts != 0 {
        return TestResult::Fail;
    }
    if snap.heartbeats != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_large_values() -> TestResult {
    let snap = stats::Snapshot {
        starts: u64::MAX,
        stops: u64::MAX,
        restarts: u64::MAX,
        heartbeats: u64::MAX,
    };
    if snap.starts != u64::MAX {
        return TestResult::Fail;
    }
    if snap.stops != u64::MAX {
        return TestResult::Fail;
    }
    if snap.restarts != u64::MAX {
        return TestResult::Fail;
    }
    if snap.heartbeats != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mark_start_increments() -> TestResult {
    let before = stats::snapshot();
    stats::mark_start();
    let after = stats::snapshot();
    if !(after.starts > before.starts) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mark_stop_increments() -> TestResult {
    let before = stats::snapshot();
    stats::mark_stop();
    let after = stats::snapshot();
    if !(after.stops > before.stops) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mark_restart_increments() -> TestResult {
    let before = stats::snapshot();
    stats::mark_restart();
    let after = stats::snapshot();
    if !(after.restarts > before.restarts) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mark_heartbeat_increments() -> TestResult {
    let before = stats::snapshot();
    stats::mark_heartbeat();
    let after = stats::snapshot();
    if !(after.heartbeats > before.heartbeats) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_string_contains_start() -> TestResult {
    stats::mark_start();
    let s = stats::as_string();
    if !s.contains("start=") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_string_contains_stop() -> TestResult {
    stats::mark_stop();
    let s = stats::as_string();
    if !s.contains("stop=") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_string_contains_restart() -> TestResult {
    stats::mark_restart();
    let s = stats::as_string();
    if !s.contains("restart=") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_string_contains_hb() -> TestResult {
    stats::mark_heartbeat();
    let s = stats::as_string();
    if !s.contains("hb=") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_string_prefix() -> TestResult {
    let s = stats::as_string();
    if !s.starts_with("rt_stats:") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_mark_start() -> TestResult {
    let before = stats::snapshot();
    stats::mark_start();
    stats::mark_start();
    stats::mark_start();
    let after = stats::snapshot();
    if after.starts != before.starts + 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_mark_stop() -> TestResult {
    let before = stats::snapshot();
    stats::mark_stop();
    stats::mark_stop();
    let after = stats::snapshot();
    if after.stops != before.stops + 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_mark_restart() -> TestResult {
    let before = stats::snapshot();
    stats::mark_restart();
    stats::mark_restart();
    stats::mark_restart();
    stats::mark_restart();
    let after = stats::snapshot();
    if after.restarts != before.restarts + 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_mark_heartbeat() -> TestResult {
    let before = stats::snapshot();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    let after = stats::snapshot();
    if after.heartbeats != before.heartbeats + 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_returns_consistent_values() -> TestResult {
    let snap1 = stats::snapshot();
    let snap2 = stats::snapshot();
    if !(snap2.starts >= snap1.starts) {
        return TestResult::Fail;
    }
    if !(snap2.stops >= snap1.stops) {
        return TestResult::Fail;
    }
    if !(snap2.restarts >= snap1.restarts) {
        return TestResult::Fail;
    }
    if !(snap2.heartbeats >= snap1.heartbeats) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_as_string_format() -> TestResult {
    let s = stats::as_string();
    if !s.contains("rt_stats:") {
        return TestResult::Fail;
    }
    if !s.contains("start=") {
        return TestResult::Fail;
    }
    if !s.contains("stop=") {
        return TestResult::Fail;
    }
    if !s.contains("restart=") {
        return TestResult::Fail;
    }
    if !s.contains("hb=") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snapshot_debug_format() -> TestResult {
    let snap = stats::snapshot();
    let debug_str = alloc::format!("{:?}", snap);
    if !debug_str.contains("starts") {
        return TestResult::Fail;
    }
    if !debug_str.contains("stops") {
        return TestResult::Fail;
    }
    if !debug_str.contains("restarts") {
        return TestResult::Fail;
    }
    if !debug_str.contains("heartbeats") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
