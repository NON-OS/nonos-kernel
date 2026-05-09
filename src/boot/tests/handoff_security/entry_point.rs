// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::boot::handoff::api::{validate_security, HandoffError};
use crate::memory::layout::constants::KERNEL_BASE;
use super::super::test_result::TestResult;

use super::helpers::baseline;

pub(crate) fn test_validate_security_rejects_entry_point_below_base() -> TestResult {
    let mut h = baseline();
    h.entry_point = KERNEL_BASE - 1;
    match validate_security(&h) {
        Err(HandoffError::EntryPointOutOfRange) => TestResult::Pass,
        _ => TestResult::Fail,
    }
}

pub(crate) fn test_validate_security_rejects_entry_point_above_window() -> TestResult {
    let mut h = baseline();
    h.entry_point = KERNEL_BASE + 0x1000_0000;
    match validate_security(&h) {
        Err(HandoffError::EntryPointOutOfRange) => TestResult::Pass,
        _ => TestResult::Fail,
    }
}

pub(crate) fn test_validate_security_accepts_entry_point_at_base() -> TestResult {
    let mut h = baseline();
    h.entry_point = KERNEL_BASE;
    if validate_security(&h).is_ok() {
        TestResult::Pass
    } else {
        TestResult::Fail
    }
}
