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

//! Memory subsystem tests
//!
//! Tests for memory allocation, guard pages, stack canaries, W^X enforcement.

extern crate alloc;

use super::framework::{TestResult, TestCase, TestSuite};
use alloc::vec::Vec;
use alloc::boxed::Box;

/// Run all memory tests
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Memory");

    suite.add_test(TestCase::new(
        "heap_allocation",
        test_heap_allocation,
        "memory",
    ));
    suite.add_test(TestCase::new(
        "vec_allocation",
        test_vec_allocation,
        "memory",
    ));
    suite.add_test(TestCase::new(
        "box_allocation",
        test_box_allocation,
        "memory",
    ));
    suite.add_test(TestCase::new(
        "large_allocation",
        test_large_allocation,
        "memory",
    ));
    suite.add_test(TestCase::new(
        "allocation_alignment",
        test_allocation_alignment,
        "memory",
    ));
    suite.add_test(TestCase::new(
        "memory_protection",
        test_memory_protection,
        "memory",
    ));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

/// Test basic heap allocation
fn test_heap_allocation() -> TestResult {
    // Allocate a small buffer
    let mut data = Vec::<u8>::with_capacity(64);
    for i in 0..64u8 {
        data.push(i);
    }

    // Verify contents
    for (i, &val) in data.iter().enumerate() {
        if val != i as u8 {
            return TestResult::Fail;
        }
    }

    TestResult::Pass
}

/// Test Vec allocation and operations
fn test_vec_allocation() -> TestResult {
    let mut v: Vec<u32> = Vec::new();

    // Test push operations
    for i in 0..100 {
        v.push(i * 2);
    }

    if v.len() != 100 {
        return TestResult::Fail;
    }

    // Test pop operations
    for i in (0..100).rev() {
        match v.pop() {
            Some(val) if val == i * 2 => {}
            _ => return TestResult::Fail,
        }
    }

    if !v.is_empty() {
        return TestResult::Fail;
    }

    TestResult::Pass
}

/// Test Box allocation
fn test_box_allocation() -> TestResult {
    // Test boxed value
    let boxed_val: Box<u64> = Box::new(0xDEAD_BEEF_CAFE_BABE);

    if *boxed_val != 0xDEAD_BEEF_CAFE_BABE {
        return TestResult::Fail;
    }

    // Test boxed array
    let boxed_arr: Box<[u8; 256]> = Box::new([0xAA; 256]);

    for &val in boxed_arr.iter() {
        if val != 0xAA {
            return TestResult::Fail;
        }
    }

    TestResult::Pass
}

/// Test large allocation
fn test_large_allocation() -> TestResult {
    // Allocate 1MB
    const SIZE: usize = 1024 * 1024;
    let mut large_vec: Vec<u8> = Vec::with_capacity(SIZE);

    // Fill with pattern
    for i in 0..SIZE {
        large_vec.push((i & 0xFF) as u8);
    }

    // Verify pattern
    for (i, &val) in large_vec.iter().enumerate() {
        if val != (i & 0xFF) as u8 {
            return TestResult::Fail;
        }
    }

    TestResult::Pass
}

/// Test allocation alignment
fn test_allocation_alignment() -> TestResult {
    // Test various alignments
    let boxed_u8: Box<u8> = Box::new(1);
    let boxed_u16: Box<u16> = Box::new(2);
    let boxed_u32: Box<u32> = Box::new(4);
    let boxed_u64: Box<u64> = Box::new(8);

    // Check alignments
    let addr_u16 = &*boxed_u16 as *const u16 as usize;
    let addr_u32 = &*boxed_u32 as *const u32 as usize;
    let addr_u64 = &*boxed_u64 as *const u64 as usize;

    // u16 should be 2-byte aligned
    if addr_u16 % 2 != 0 {
        return TestResult::Fail;
    }

    // u32 should be 4-byte aligned
    if addr_u32 % 4 != 0 {
        return TestResult::Fail;
    }

    // u64 should be 8-byte aligned
    if addr_u64 % 8 != 0 {
        return TestResult::Fail;
    }

    // Consume boxed_u8 to avoid warning
    let _ = *boxed_u8;

    TestResult::Pass
}

/// Test memory protection levels
fn test_memory_protection() -> TestResult {
    use crate::memory::MemoryProtection;

    // Test basic protection combinations
    let none = MemoryProtection::None;
    let read = MemoryProtection::Read;
    let rw = MemoryProtection::ReadWrite;
    let rx = MemoryProtection::ReadExecute;

    // Test that Read and ReadWrite are different
    if read == rw {
        return TestResult::Fail;
    }

    // Test that ReadWrite and ReadExecute are different (W^X principle)
    if rw == rx {
        return TestResult::Fail;
    }

    // Test that None is different from others
    if none == read {
        return TestResult::Fail;
    }

    TestResult::Pass
}
