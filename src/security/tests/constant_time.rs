use crate::security::*;

#[test]
fn test_ct_compare_equal_slices() {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 5];
    assert!(ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_unequal_slices() {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 6];
    assert!(!ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_different_lengths() {
    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4];
    assert!(!ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_empty_slices() {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    assert!(ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_single_byte_equal() {
    let a = [0xABu8];
    let b = [0xABu8];
    assert!(ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_single_byte_unequal() {
    let a = [0xABu8];
    let b = [0xBAu8];
    assert!(!ct_compare(&a, &b));
}

#[test]
fn test_ct_verify_equal() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert_eq!(ct_verify(&a, &b), CtVerifyResult::Equal);
}

#[test]
fn test_ct_verify_not_equal() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    assert_eq!(ct_verify(&a, &b), CtVerifyResult::NotEqual);
}

#[test]
fn test_ct_verify_result_equality() {
    assert_eq!(CtVerifyResult::Equal, CtVerifyResult::Equal);
    assert_eq!(CtVerifyResult::NotEqual, CtVerifyResult::NotEqual);
    assert_ne!(CtVerifyResult::Equal, CtVerifyResult::NotEqual);
}

#[test]
fn test_ct_select_u8_condition_true() {
    let result = ct_select_u8(1, 0xAA, 0xBB);
    assert_eq!(result, 0xAA);
}

#[test]
fn test_ct_select_u8_condition_false() {
    let result = ct_select_u8(0, 0xAA, 0xBB);
    assert_eq!(result, 0xBB);
}

#[test]
fn test_ct_select_u32_condition_true() {
    let result = ct_select_u32(1, 0xDEADBEEF, 0xCAFEBABE);
    assert_eq!(result, 0xDEADBEEF);
}

#[test]
fn test_ct_select_u32_condition_false() {
    let result = ct_select_u32(0, 0xDEADBEEF, 0xCAFEBABE);
    assert_eq!(result, 0xCAFEBABE);
}

#[test]
fn test_ct_select_u64_condition_true() {
    let result = ct_select_u64(1, 0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF);
    assert_eq!(result, 0xDEADBEEFCAFEBABE);
}

#[test]
fn test_ct_select_u64_condition_false() {
    let result = ct_select_u64(0, 0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF);
    assert_eq!(result, 0x1234567890ABCDEF);
}

#[test]
fn test_ct_select_slice_condition_true() {
    let mut dst = [1u8, 2, 3, 4];
    let src = [5u8, 6, 7, 8];
    ct_select_slice(1, &mut dst, &src);
    assert_eq!(dst, [5u8, 6, 7, 8]);
}

#[test]
fn test_ct_select_slice_condition_false() {
    let mut dst = [1u8, 2, 3, 4];
    let src = [5u8, 6, 7, 8];
    ct_select_slice(0, &mut dst, &src);
    assert_eq!(dst, [1u8, 2, 3, 4]);
}

#[test]
fn test_ct_swap_slices_condition_true() {
    let mut a = [1u8, 2, 3, 4];
    let mut b = [5u8, 6, 7, 8];
    ct_swap_slices(1, &mut a, &mut b);
    assert_eq!(a, [5u8, 6, 7, 8]);
    assert_eq!(b, [1u8, 2, 3, 4]);
}

#[test]
fn test_ct_swap_slices_condition_false() {
    let mut a = [1u8, 2, 3, 4];
    let mut b = [5u8, 6, 7, 8];
    ct_swap_slices(0, &mut a, &mut b);
    assert_eq!(a, [1u8, 2, 3, 4]);
    assert_eq!(b, [5u8, 6, 7, 8]);
}

#[test]
fn test_ct_lt_u32_less_than() {
    assert_eq!(ct_lt_u32(5, 10), 1);
}

#[test]
fn test_ct_lt_u32_equal() {
    assert_eq!(ct_lt_u32(10, 10), 0);
}

#[test]
fn test_ct_lt_u32_greater_than() {
    assert_eq!(ct_lt_u32(15, 10), 0);
}

#[test]
fn test_ct_lt_u64_less_than() {
    assert_eq!(ct_lt_u64(100, 200), 1);
}

#[test]
fn test_ct_lt_u64_equal() {
    assert_eq!(ct_lt_u64(200, 200), 0);
}

#[test]
fn test_ct_lt_u64_greater_than() {
    assert_eq!(ct_lt_u64(300, 200), 0);
}

#[test]
fn test_ct_gt_u32_greater_than() {
    assert_eq!(ct_gt_u32(15, 10), 1);
}

#[test]
fn test_ct_gt_u32_equal() {
    assert_eq!(ct_gt_u32(10, 10), 0);
}

#[test]
fn test_ct_gt_u32_less_than() {
    assert_eq!(ct_gt_u32(5, 10), 0);
}

#[test]
fn test_ct_eq_u32_equal() {
    assert_eq!(ct_eq_u32(42, 42), 1);
}

#[test]
fn test_ct_eq_u32_not_equal() {
    assert_eq!(ct_eq_u32(42, 43), 0);
}

#[test]
fn test_ct_eq_u64_equal() {
    assert_eq!(ct_eq_u64(0xDEADBEEF, 0xDEADBEEF), 1);
}

#[test]
fn test_ct_eq_u64_not_equal() {
    assert_eq!(ct_eq_u64(0xDEADBEEF, 0xCAFEBABE), 0);
}

#[test]
fn test_ct_min_u32() {
    assert_eq!(ct_min_u32(5, 10), 5);
    assert_eq!(ct_min_u32(10, 5), 5);
    assert_eq!(ct_min_u32(7, 7), 7);
}

#[test]
fn test_ct_max_u32() {
    assert_eq!(ct_max_u32(5, 10), 10);
    assert_eq!(ct_max_u32(10, 5), 10);
    assert_eq!(ct_max_u32(7, 7), 7);
}

#[test]
fn test_ct_copy_bounded_full_copy() {
    let mut dst = [0u8; 4];
    let src = [1u8, 2, 3, 4];
    ct_copy_bounded(&mut dst, &src, 4);
    assert_eq!(dst, [1u8, 2, 3, 4]);
}

#[test]
fn test_ct_copy_bounded_partial_copy() {
    let mut dst = [0u8; 4];
    let src = [1u8, 2, 3, 4];
    ct_copy_bounded(&mut dst, &src, 2);
    assert_eq!(dst, [1u8, 2, 0, 0]);
}

#[test]
fn test_ct_copy_bounded_zero_length() {
    let mut dst = [0xFFu8; 4];
    let src = [1u8, 2, 3, 4];
    ct_copy_bounded(&mut dst, &src, 0);
    assert_eq!(dst, [0xFFu8; 4]);
}

#[test]
fn test_ct_zero_slice() {
    let mut data = [1u8, 2, 3, 4, 5];
    ct_zero(&mut data);
    assert_eq!(data, [0u8; 5]);
}

#[test]
fn test_ct_zero_u64_slice() {
    let mut data = [0xDEADBEEFu64, 0xCAFEBABE];
    ct_zero_u64(&mut data);
    assert_eq!(data, [0u64; 2]);
}

#[test]
fn test_ct_hmac_verify_matching() {
    let computed = [0xABu8; 32];
    let expected = [0xABu8; 32];
    assert!(ct_hmac_verify(&computed, &expected));
}

#[test]
fn test_ct_hmac_verify_non_matching() {
    let computed = [0xABu8; 32];
    let expected = [0xCDu8; 32];
    assert!(!ct_hmac_verify(&computed, &expected));
}

#[test]
fn test_ct_signature_verify_matching() {
    let computed = [0x11u8; 64];
    let expected = [0x11u8; 64];
    assert!(ct_signature_verify(&computed, &expected));
}

#[test]
fn test_ct_signature_verify_non_matching() {
    let computed = [0x11u8; 64];
    let expected = [0x22u8; 64];
    assert!(!ct_signature_verify(&computed, &expected));
}

#[test]
fn test_timing_mode_variants() {
    let _ = TimingMode::Quick;
    let _ = TimingMode::Statistical;
}

#[test]
fn test_self_test_result_fields() {
    let result = SelfTestResult {
        passed: true,
        tests_run: 10,
        tests_passed: 10,
        failure_description: None,
    };
    assert!(result.passed);
    assert_eq!(result.tests_run, 10);
    assert_eq!(result.tests_passed, 10);
    assert!(result.failure_description.is_none());
}

#[test]
fn test_self_test_result_with_failure() {
    let result = SelfTestResult {
        passed: false,
        tests_run: 10,
        tests_passed: 8,
        failure_description: Some("Test failed"),
    };
    assert!(!result.passed);
    assert_eq!(result.tests_run, 10);
    assert_eq!(result.tests_passed, 8);
    assert_eq!(result.failure_description, Some("Test failed"));
}

#[test]
fn test_ct_verify_result_invalid_input_variant() {
    let _ = CtVerifyResult::InvalidInput;
}

#[test]
fn test_ct_compare_all_zeros() {
    let a = [0u8; 32];
    let b = [0u8; 32];
    assert!(ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_all_ones() {
    let a = [0xFFu8; 32];
    let b = [0xFFu8; 32];
    assert!(ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_first_byte_differs() {
    let a = [0u8, 1, 2, 3];
    let b = [1u8, 1, 2, 3];
    assert!(!ct_compare(&a, &b));
}

#[test]
fn test_ct_compare_last_byte_differs() {
    let a = [0u8, 1, 2, 3];
    let b = [0u8, 1, 2, 4];
    assert!(!ct_compare(&a, &b));
}
