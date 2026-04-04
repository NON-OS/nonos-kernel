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

use crate::sched::*;

#[test]
fn test_priority_values() {
    assert_eq!(Priority::Idle as u8, 0);
    assert_eq!(Priority::Low as u8, 1);
    assert_eq!(Priority::Normal as u8, 2);
    assert_eq!(Priority::High as u8, 3);
    assert_eq!(Priority::Critical as u8, 4);
    assert_eq!(Priority::RealTime as u8, 5);
}

#[test]
fn test_priority_ordering() {
    assert!(Priority::RealTime > Priority::Critical);
    assert!(Priority::Critical > Priority::High);
    assert!(Priority::High > Priority::Normal);
    assert!(Priority::Normal > Priority::Low);
    assert!(Priority::Low > Priority::Idle);
}

#[test]
fn test_priority_equality() {
    assert_eq!(Priority::Normal, Priority::Normal);
    assert_ne!(Priority::High, Priority::Low);
}

#[test]
fn test_priority_clone() {
    let p1 = Priority::High;
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn test_priority_copy() {
    let p1 = Priority::Critical;
    let p2 = p1;
    assert_eq!(p1, p2);
}

#[test]
fn test_priority_partial_ord() {
    assert!(Priority::RealTime >= Priority::Critical);
    assert!(Priority::Idle <= Priority::Low);
    assert!(Priority::Normal <= Priority::Normal);
    assert!(Priority::High >= Priority::High);
}

#[test]
fn test_priority_debug() {
    let debug_str = alloc::format!("{:?}", Priority::Normal);
    assert!(debug_str.contains("Normal"));
}

#[test]
fn test_all_priority_variants_unique() {
    let priorities = [
        Priority::Idle,
        Priority::Low,
        Priority::Normal,
        Priority::High,
        Priority::Critical,
        Priority::RealTime,
    ];
    for i in 0..priorities.len() {
        for j in (i + 1)..priorities.len() {
            assert_ne!(priorities[i], priorities[j]);
        }
    }
}

#[test]
fn test_priority_ord_consistency() {
    let mut priorities = [
        Priority::High,
        Priority::Idle,
        Priority::RealTime,
        Priority::Normal,
        Priority::Low,
        Priority::Critical,
    ];
    priorities.sort();
    assert_eq!(priorities[0], Priority::Idle);
    assert_eq!(priorities[1], Priority::Low);
    assert_eq!(priorities[2], Priority::Normal);
    assert_eq!(priorities[3], Priority::High);
    assert_eq!(priorities[4], Priority::Critical);
    assert_eq!(priorities[5], Priority::RealTime);
}
