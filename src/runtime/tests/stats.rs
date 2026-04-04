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

#[test]
fn test_snapshot_debug() {
    let snap = stats::Snapshot {
        starts: 1,
        stops: 2,
        restarts: 3,
        heartbeats: 4,
    };
    let debug_str = alloc::format!("{:?}", snap);
    assert!(debug_str.contains("Snapshot"));
}

#[test]
fn test_snapshot_clone() {
    let snap = stats::Snapshot {
        starts: 10,
        stops: 20,
        restarts: 30,
        heartbeats: 40,
    };
    let cloned = snap.clone();
    assert_eq!(snap.starts, cloned.starts);
    assert_eq!(snap.stops, cloned.stops);
    assert_eq!(snap.restarts, cloned.restarts);
    assert_eq!(snap.heartbeats, cloned.heartbeats);
}

#[test]
fn test_snapshot_starts_field() {
    let snap = stats::Snapshot {
        starts: 100,
        stops: 0,
        restarts: 0,
        heartbeats: 0,
    };
    assert_eq!(snap.starts, 100);
}

#[test]
fn test_snapshot_stops_field() {
    let snap = stats::Snapshot {
        starts: 0,
        stops: 200,
        restarts: 0,
        heartbeats: 0,
    };
    assert_eq!(snap.stops, 200);
}

#[test]
fn test_snapshot_restarts_field() {
    let snap = stats::Snapshot {
        starts: 0,
        stops: 0,
        restarts: 300,
        heartbeats: 0,
    };
    assert_eq!(snap.restarts, 300);
}

#[test]
fn test_snapshot_heartbeats_field() {
    let snap = stats::Snapshot {
        starts: 0,
        stops: 0,
        restarts: 0,
        heartbeats: 400,
    };
    assert_eq!(snap.heartbeats, 400);
}

#[test]
fn test_snapshot_all_zeros() {
    let snap = stats::Snapshot {
        starts: 0,
        stops: 0,
        restarts: 0,
        heartbeats: 0,
    };
    assert_eq!(snap.starts, 0);
    assert_eq!(snap.stops, 0);
    assert_eq!(snap.restarts, 0);
    assert_eq!(snap.heartbeats, 0);
}

#[test]
fn test_snapshot_large_values() {
    let snap = stats::Snapshot {
        starts: u64::MAX,
        stops: u64::MAX,
        restarts: u64::MAX,
        heartbeats: u64::MAX,
    };
    assert_eq!(snap.starts, u64::MAX);
    assert_eq!(snap.stops, u64::MAX);
    assert_eq!(snap.restarts, u64::MAX);
    assert_eq!(snap.heartbeats, u64::MAX);
}

#[test]
fn test_mark_start_increments() {
    let before = stats::snapshot();
    stats::mark_start();
    let after = stats::snapshot();
    assert!(after.starts > before.starts);
}

#[test]
fn test_mark_stop_increments() {
    let before = stats::snapshot();
    stats::mark_stop();
    let after = stats::snapshot();
    assert!(after.stops > before.stops);
}

#[test]
fn test_mark_restart_increments() {
    let before = stats::snapshot();
    stats::mark_restart();
    let after = stats::snapshot();
    assert!(after.restarts > before.restarts);
}

#[test]
fn test_mark_heartbeat_increments() {
    let before = stats::snapshot();
    stats::mark_heartbeat();
    let after = stats::snapshot();
    assert!(after.heartbeats > before.heartbeats);
}

#[test]
fn test_as_string_contains_start() {
    stats::mark_start();
    let s = stats::as_string();
    assert!(s.contains("start="));
}

#[test]
fn test_as_string_contains_stop() {
    stats::mark_stop();
    let s = stats::as_string();
    assert!(s.contains("stop="));
}

#[test]
fn test_as_string_contains_restart() {
    stats::mark_restart();
    let s = stats::as_string();
    assert!(s.contains("restart="));
}

#[test]
fn test_as_string_contains_hb() {
    stats::mark_heartbeat();
    let s = stats::as_string();
    assert!(s.contains("hb="));
}

#[test]
fn test_as_string_prefix() {
    let s = stats::as_string();
    assert!(s.starts_with("rt_stats:"));
}

#[test]
fn test_multiple_mark_start() {
    let before = stats::snapshot();
    stats::mark_start();
    stats::mark_start();
    stats::mark_start();
    let after = stats::snapshot();
    assert_eq!(after.starts, before.starts + 3);
}

#[test]
fn test_multiple_mark_stop() {
    let before = stats::snapshot();
    stats::mark_stop();
    stats::mark_stop();
    let after = stats::snapshot();
    assert_eq!(after.stops, before.stops + 2);
}

#[test]
fn test_multiple_mark_restart() {
    let before = stats::snapshot();
    stats::mark_restart();
    stats::mark_restart();
    stats::mark_restart();
    stats::mark_restart();
    let after = stats::snapshot();
    assert_eq!(after.restarts, before.restarts + 4);
}

#[test]
fn test_multiple_mark_heartbeat() {
    let before = stats::snapshot();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    stats::mark_heartbeat();
    let after = stats::snapshot();
    assert_eq!(after.heartbeats, before.heartbeats + 5);
}

#[test]
fn test_snapshot_returns_consistent_values() {
    let snap1 = stats::snapshot();
    let snap2 = stats::snapshot();
    assert!(snap2.starts >= snap1.starts);
    assert!(snap2.stops >= snap1.stops);
    assert!(snap2.restarts >= snap1.restarts);
    assert!(snap2.heartbeats >= snap1.heartbeats);
}

#[test]
fn test_as_string_format() {
    let s = stats::as_string();
    assert!(s.contains("rt_stats:"));
    assert!(s.contains("start="));
    assert!(s.contains("stop="));
    assert!(s.contains("restart="));
    assert!(s.contains("hb="));
}

#[test]
fn test_snapshot_debug_format() {
    let snap = stats::snapshot();
    let debug_str = alloc::format!("{:?}", snap);
    assert!(debug_str.contains("starts"));
    assert!(debug_str.contains("stops"));
    assert!(debug_str.contains("restarts"));
    assert!(debug_str.contains("heartbeats"));
}
