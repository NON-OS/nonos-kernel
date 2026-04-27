// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Constant-time operation tests

use crate::crypto::util::constant_time::*;
use crate::test::framework::TestResult;

pub(crate) fn test_ct_eq_equal() -> TestResult {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    if !ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_not_equal() -> TestResult {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    if ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_different_lengths() -> TestResult {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3];
    if ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_empty() -> TestResult {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    if !ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u64_false() -> TestResult {
    let a: u64 = 10;
    let b: u64 = 20;
    if ct_select_u64(false, a, b) != b {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u64_true() -> TestResult {
    let a: u64 = 10;
    let b: u64 = 20;
    if ct_select_u64(true, a, b) != a {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_is_zero_u64_zero() -> TestResult {
    if ct_is_zero_u64(0) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_is_zero_u64_one() -> TestResult {
    if ct_is_zero_u64(1) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_is_zero_u64_max() -> TestResult {
    if ct_is_zero_u64(u64::MAX) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero() -> TestResult {
    let mut data = [1u8, 2, 3, 4];
    secure_zero(&mut data);
    if data != [0, 0, 0, 0] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero_large() -> TestResult {
    let mut data = [0xffu8; 256];
    secure_zero(&mut data);
    if data != [0u8; 256] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_secure_zero_empty() -> TestResult {
    let mut data: [u8; 0] = [];
    secure_zero(&mut data);
    TestResult::Pass
}
