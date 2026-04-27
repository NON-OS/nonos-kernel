// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Constant-time operation tests for security subsystem

use crate::security::*;
use crate::test::framework::TestResult;

pub(crate) fn test_ct_compare_equal_slices() -> TestResult {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 5];
    if !ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_unequal_slices() -> TestResult {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 6];
    if ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_different_lengths() -> TestResult {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4];
    if ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_empty_slices() -> TestResult {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    if !ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_single_byte_equal() -> TestResult {
    let a = [0xABu8];
    let b = [0xABu8];
    if !ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_single_byte_unequal() -> TestResult {
    let a = [0xABu8];
    let b = [0xBAu8];
    if ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_verify_equal() -> TestResult {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    if ct_verify(&a, &b) != CtVerifyResult::Equal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_verify_not_equal() -> TestResult {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    if ct_verify(&a, &b) != CtVerifyResult::NotEqual {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_verify_result_equality() -> TestResult {
    if CtVerifyResult::Equal != CtVerifyResult::Equal {
        return TestResult::Fail;
    }
    if CtVerifyResult::NotEqual != CtVerifyResult::NotEqual {
        return TestResult::Fail;
    }
    if CtVerifyResult::Equal == CtVerifyResult::NotEqual {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u8_condition_true() -> TestResult {
    let result = ct_select_u8(1, 0xAA, 0xBB);
    if result != 0xAA {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u8_condition_false() -> TestResult {
    let result = ct_select_u8(0, 0xAA, 0xBB);
    if result != 0xBB {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u32_condition_true() -> TestResult {
    let result = ct_select_u32(1, 0xDEADBEEF, 0xCAFEBABE);
    if result != 0xDEADBEEF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u32_condition_false() -> TestResult {
    let result = ct_select_u32(0, 0xDEADBEEF, 0xCAFEBABE);
    if result != 0xCAFEBABE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u64_condition_true() -> TestResult {
    let result = ct_select_u64(1, 0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF);
    if result != 0xDEADBEEFCAFEBABE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_u64_condition_false() -> TestResult {
    let result = ct_select_u64(0, 0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF);
    if result != 0x1234567890ABCDEF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_slice_condition_true() -> TestResult {
    let mut dst = [1u8, 2, 3, 4];
    let src = [5u8, 6, 7, 8];
    ct_select_slice(1, &mut dst, &src);
    if dst != [5u8, 6, 7, 8] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_select_slice_condition_false() -> TestResult {
    let mut dst = [1u8, 2, 3, 4];
    let src = [5u8, 6, 7, 8];
    ct_select_slice(0, &mut dst, &src);
    if dst != [1u8, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_swap_slices_condition_true() -> TestResult {
    let mut a = [1u8, 2, 3, 4];
    let mut b = [5u8, 6, 7, 8];
    ct_swap_slices(1, &mut a, &mut b);
    if a != [5u8, 6, 7, 8] {
        return TestResult::Fail;
    }
    if b != [1u8, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_swap_slices_condition_false() -> TestResult {
    let mut a = [1u8, 2, 3, 4];
    let mut b = [5u8, 6, 7, 8];
    ct_swap_slices(0, &mut a, &mut b);
    if a != [1u8, 2, 3, 4] {
        return TestResult::Fail;
    }
    if b != [5u8, 6, 7, 8] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_lt_u32_less_than() -> TestResult {
    if ct_lt_u32(5, 10) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_lt_u32_equal() -> TestResult {
    if ct_lt_u32(10, 10) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_lt_u32_greater_than() -> TestResult {
    if ct_lt_u32(15, 10) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_lt_u64_less_than() -> TestResult {
    if ct_lt_u64(100, 200) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_lt_u64_equal() -> TestResult {
    if ct_lt_u64(200, 200) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_lt_u64_greater_than() -> TestResult {
    if ct_lt_u64(300, 200) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_gt_u32_greater_than() -> TestResult {
    if ct_gt_u32(15, 10) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_gt_u32_equal() -> TestResult {
    if ct_gt_u32(10, 10) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_gt_u32_less_than() -> TestResult {
    if ct_gt_u32(5, 10) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_u32_equal() -> TestResult {
    if ct_eq_u32(42, 42) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_u32_not_equal() -> TestResult {
    if ct_eq_u32(42, 43) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_u64_equal() -> TestResult {
    if ct_eq_u64(0xDEADBEEF, 0xDEADBEEF) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_eq_u64_not_equal() -> TestResult {
    if ct_eq_u64(0xDEADBEEF, 0xCAFEBABE) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_min_u32() -> TestResult {
    if ct_min_u32(5, 10) != 5 {
        return TestResult::Fail;
    }
    if ct_min_u32(10, 5) != 5 {
        return TestResult::Fail;
    }
    if ct_min_u32(7, 7) != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_max_u32() -> TestResult {
    if ct_max_u32(5, 10) != 10 {
        return TestResult::Fail;
    }
    if ct_max_u32(10, 5) != 10 {
        return TestResult::Fail;
    }
    if ct_max_u32(7, 7) != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_copy_bounded_full_copy() -> TestResult {
    let mut dst = [0u8; 4];
    let src = [1u8, 2, 3, 4];
    ct_copy_bounded(&mut dst, &src, 4);
    if dst != [1u8, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_copy_bounded_partial_copy() -> TestResult {
    let mut dst = [0u8; 4];
    let src = [1u8, 2, 3, 4];
    ct_copy_bounded(&mut dst, &src, 2);
    if dst != [1u8, 2, 0, 0] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_copy_bounded_zero_length() -> TestResult {
    let mut dst = [0xFFu8; 4];
    let src = [1u8, 2, 3, 4];
    ct_copy_bounded(&mut dst, &src, 0);
    if dst != [0xFFu8; 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_zero_slice() -> TestResult {
    let mut data = [1u8, 2, 3, 4, 5];
    ct_zero(&mut data);
    if data != [0u8; 5] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_zero_u64_slice() -> TestResult {
    let mut data = [0xDEADBEEFu64, 0xCAFEBABE];
    ct_zero_u64(&mut data);
    if data != [0u64; 2] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_hmac_verify_matching() -> TestResult {
    let computed = [0xABu8; 32];
    let expected = [0xABu8; 32];
    if !ct_hmac_verify(&computed, &expected) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_hmac_verify_non_matching() -> TestResult {
    let computed = [0xABu8; 32];
    let expected = [0xCDu8; 32];
    if ct_hmac_verify(&computed, &expected) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_signature_verify_matching() -> TestResult {
    let computed = [0x11u8; 64];
    let expected = [0x11u8; 64];
    if !ct_signature_verify(&computed, &expected) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_signature_verify_non_matching() -> TestResult {
    let computed = [0x11u8; 64];
    let expected = [0x22u8; 64];
    if ct_signature_verify(&computed, &expected) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_timing_mode_variants() -> TestResult {
    let _ = TimingMode::Quick;
    let _ = TimingMode::Statistical;
    TestResult::Pass
}

pub(crate) fn test_self_test_result_fields() -> TestResult {
    let result =
        SelfTestResult { passed: true, tests_run: 10, tests_passed: 10, failure_description: None };
    if !result.passed {
        return TestResult::Fail;
    }
    if result.tests_run != 10 {
        return TestResult::Fail;
    }
    if result.tests_passed != 10 {
        return TestResult::Fail;
    }
    if result.failure_description.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_self_test_result_with_failure() -> TestResult {
    let result = SelfTestResult {
        passed: false,
        tests_run: 10,
        tests_passed: 8,
        failure_description: Some("Test failed"),
    };
    if result.passed {
        return TestResult::Fail;
    }
    if result.tests_run != 10 {
        return TestResult::Fail;
    }
    if result.tests_passed != 8 {
        return TestResult::Fail;
    }
    if result.failure_description != Some("Test failed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_verify_result_invalid_input_variant() -> TestResult {
    let _ = CtVerifyResult::InvalidInput;
    TestResult::Pass
}

pub(crate) fn test_ct_compare_all_zeros() -> TestResult {
    let a = [0u8; 32];
    let b = [0u8; 32];
    if !ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_all_ones() -> TestResult {
    let a = [0xFFu8; 32];
    let b = [0xFFu8; 32];
    if !ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_first_byte_differs() -> TestResult {
    let a = [0u8, 1, 2, 3];
    let b = [1u8, 1, 2, 3];
    if ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ct_compare_last_byte_differs() -> TestResult {
    let a = [0u8, 1, 2, 3];
    let b = [0u8, 1, 2, 4];
    if ct_compare(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
