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

#[test]
fn test_stats_default_read_ops() {
    let stats = AhciStats::default();
    assert_eq!(stats.read_ops, 0);
}

#[test]
fn test_stats_default_write_ops() {
    let stats = AhciStats::default();
    assert_eq!(stats.write_ops, 0);
}

#[test]
fn test_stats_default_trim_ops() {
    let stats = AhciStats::default();
    assert_eq!(stats.trim_ops, 0);
}

#[test]
fn test_stats_default_errors() {
    let stats = AhciStats::default();
    assert_eq!(stats.errors, 0);
}

#[test]
fn test_stats_default_bytes_read() {
    let stats = AhciStats::default();
    assert_eq!(stats.bytes_read, 0);
}

#[test]
fn test_stats_default_bytes_written() {
    let stats = AhciStats::default();
    assert_eq!(stats.bytes_written, 0);
}

#[test]
fn test_stats_default_devices_count() {
    let stats = AhciStats::default();
    assert_eq!(stats.devices_count, 0);
}

#[test]
fn test_stats_default_port_resets() {
    let stats = AhciStats::default();
    assert_eq!(stats.port_resets, 0);
}

#[test]
fn test_stats_default_validation_failures() {
    let stats = AhciStats::default();
    assert_eq!(stats.validation_failures, 0);
}

#[test]
fn test_stats_copy() {
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
    assert_eq!(stats1.read_ops, stats2.read_ops);
    assert_eq!(stats1.write_ops, stats2.write_ops);
    assert_eq!(stats1.trim_ops, stats2.trim_ops);
    assert_eq!(stats1.errors, stats2.errors);
    assert_eq!(stats1.bytes_read, stats2.bytes_read);
    assert_eq!(stats1.bytes_written, stats2.bytes_written);
    assert_eq!(stats1.devices_count, stats2.devices_count);
    assert_eq!(stats1.port_resets, stats2.port_resets);
    assert_eq!(stats1.validation_failures, stats2.validation_failures);
}

#[test]
fn test_stats_clone() {
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
    assert_eq!(stats1.read_ops, stats2.read_ops);
    assert_eq!(stats1.bytes_read, stats2.bytes_read);
}

#[test]
fn test_stats_debug() {
    let stats = AhciStats::default();
    let debug_str = format!("{:?}", stats);
    assert!(debug_str.contains("AhciStats"));
    assert!(debug_str.contains("read_ops"));
    assert!(debug_str.contains("write_ops"));
}

#[test]
fn test_stats_field_independence() {
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

    assert_eq!(stats.read_ops, 1);
    assert_eq!(stats.write_ops, 2);
    assert_eq!(stats.trim_ops, 3);
    assert_eq!(stats.errors, 4);
    assert_eq!(stats.bytes_read, 5);
    assert_eq!(stats.bytes_written, 6);
    assert_eq!(stats.devices_count, 7);
    assert_eq!(stats.port_resets, 8);
    assert_eq!(stats.validation_failures, 9);
}

#[test]
fn test_stats_large_values() {
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

    assert_eq!(stats.read_ops, u64::MAX);
    assert_eq!(stats.devices_count, u32::MAX);
}
