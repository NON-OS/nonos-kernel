// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;

#[test]
fn test_monster_stats_new() {
    let stats = MonsterStats::new();
    assert_eq!(stats.pci_devices, 0);
    assert_eq!(stats.nvme_bytes_rw, 0);
    assert_eq!(stats.usb_devices, 0);
    assert_eq!(stats.net_rx, 0);
    assert_eq!(stats.net_tx, 0);
    assert_eq!(stats.gpu_memory, 0);
    assert_eq!(stats.audio_streams, 0);
    assert_eq!(stats.errors, 0);
    assert_eq!(stats.ticks, 0);
}

#[test]
fn test_monster_stats_default() {
    let stats: MonsterStats = Default::default();
    assert_eq!(stats.pci_devices, 0);
    assert_eq!(stats.errors, 0);
}

#[test]
fn test_monster_stats_clone() {
    let mut stats = MonsterStats::new();
    stats.pci_devices = 10;
    stats.errors = 2;

    let cloned = stats.clone();
    assert_eq!(cloned.pci_devices, 10);
    assert_eq!(cloned.errors, 2);
}

#[test]
fn test_monster_stats_tick() {
    let mut stats = MonsterStats::new();
    assert_eq!(stats.ticks, 0);

    stats.tick();
    assert_eq!(stats.ticks, 1);

    for _ in 0..100 {
        stats.tick();
    }
    assert_eq!(stats.ticks, 101);
}

#[test]
fn test_monster_stats_error() {
    let mut stats = MonsterStats::new();
    assert_eq!(stats.errors, 0);

    stats.record_error();
    assert_eq!(stats.errors, 1);

    stats.record_error();
    stats.record_error();
    assert_eq!(stats.errors, 3);
}

#[test]
fn test_monster_stats_debug() {
    let stats = MonsterStats::new();
    let debug_str = format!("{:?}", stats);
    assert!(debug_str.contains("MonsterStats"));
    assert!(debug_str.contains("pci_devices"));
}
