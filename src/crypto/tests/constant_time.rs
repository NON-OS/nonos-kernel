use crate::crypto::util::constant_time::*;

#[test]
fn test_ct_eq_equal() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    assert!(ct_eq(&a, &b));
}

#[test]
fn test_ct_eq_not_equal() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 5];
    assert!(!ct_eq(&a, &b));
}

#[test]
fn test_ct_select_u64() {
    let a: u64 = 10;
    let b: u64 = 20;
    assert_eq!(ct_select_u64(false, a, b), b);
    assert_eq!(ct_select_u64(true, a, b), a);
}

#[test]
fn test_ct_is_zero_u64() {
    assert_eq!(ct_is_zero_u64(0), 1);
    assert_eq!(ct_is_zero_u64(1), 0);
}

#[test]
fn test_secure_zero() {
    let mut data = [1u8, 2, 3, 4];
    secure_zero(&mut data);
    assert_eq!(data, [0, 0, 0, 0]);
}
