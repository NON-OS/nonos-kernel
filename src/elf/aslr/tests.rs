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

use super::*;

#[test]
fn test_aslr_manager_new() {
    let manager = AslrManager::new();
    assert!(manager.is_executable_randomization_enabled());
    assert!(manager.is_stack_randomization_enabled());
    assert!(manager.is_heap_randomization_enabled());
}

#[test]
fn test_aslr_manager_disabled() {
    let manager = AslrManager::disabled();
    assert!(!manager.is_executable_randomization_enabled());
    assert!(!manager.is_stack_randomization_enabled());
    assert!(!manager.is_heap_randomization_enabled());
}

#[test]
fn test_aslr_manager_with_settings() {
    let manager = AslrManager::with_settings(true, false, true);
    assert!(manager.is_stack_randomization_enabled());
    assert!(!manager.is_heap_randomization_enabled());
    assert!(manager.is_executable_randomization_enabled());
}

#[test]
fn test_random_offset_zero_max() {
    let mut manager = AslrManager::new();
    assert_eq!(manager.random_offset(0), 0);
}

#[test]
fn test_random_offset_within_range() {
    let mut manager = AslrManager::new();
    for _ in 0..100 {
        let offset = manager.random_offset(1000);
        assert!(offset < 1000);
    }
}

#[test]
fn test_randomize_base_disabled() {
    let mut manager = AslrManager::disabled();
    let base = 0x400000;
    assert_eq!(manager.randomize_base(base), base);
}

#[test]
fn test_randomize_base_page_aligned() {
    let mut manager = AslrManager::new();
    let result = manager.randomize_base(0x400000);
    assert_eq!(result & 0xFFF, 0);
}

#[test]
fn test_randomize_stack_disabled() {
    let mut manager = AslrManager::disabled();
    let base = 0x7FFFFFFFE000;
    assert_eq!(manager.randomize_stack(base), base);
}

#[test]
fn test_randomize_stack_below_base() {
    let mut manager = AslrManager::new();
    let base = 0x7FFFFFFFE000;
    let result = manager.randomize_stack(base);
    assert!(result <= base);
    assert_eq!(result & 0xFFF, 0);
}

#[test]
fn test_randomize_heap_disabled() {
    let mut manager = AslrManager::disabled();
    let base = 0x10000000;
    assert_eq!(manager.randomize_heap(base), base);
}

#[test]
fn test_randomize_heap_above_base() {
    let mut manager = AslrManager::new();
    let base = 0x10000000;
    let result = manager.randomize_heap(base);
    assert!(result >= base);
    assert_eq!(result & 0xFFF, 0);
}

#[test]
fn test_set_randomization() {
    let mut manager = AslrManager::new();

    manager.set_executable_randomization(false);
    assert!(!manager.is_executable_randomization_enabled());

    manager.set_stack_randomization(false);
    assert!(!manager.is_stack_randomization_enabled());

    manager.set_heap_randomization(false);
    assert!(!manager.is_heap_randomization_enabled());
}

#[test]
fn test_reseed() {
    let mut manager = AslrManager::new();
    let _before = manager.entropy();
    manager.reseed();
    let _ = manager.entropy();
}

#[test]
fn test_default() {
    let manager = AslrManager::default();
    assert!(manager.is_executable_randomization_enabled());
}

#[test]
fn test_constants() {
    assert_eq!(EXEC_RANDOMIZATION_RANGE, 0x40000000);
    assert_eq!(STACK_RANDOMIZATION_RANGE, 0x1000000);
    assert_eq!(HEAP_RANDOMIZATION_RANGE, 0x2000000);
}
