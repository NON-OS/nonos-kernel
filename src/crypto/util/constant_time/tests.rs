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
fn test_ct_eq() {
    let a = [1u8, 2, 3, 4];
    let b = [1u8, 2, 3, 4];
    let c = [1u8, 2, 3, 5];

    assert!(ct_eq(&a, &b));
    assert!(!ct_eq(&a, &c));
    assert!(!ct_eq(&a, &[1, 2, 3]));
}

#[test]
fn test_ct_select() {
    assert_eq!(ct_select_u8(true, 0xAA, 0x55), 0xAA);
    assert_eq!(ct_select_u8(false, 0xAA, 0x55), 0x55);
    assert_eq!(ct_select_u64(true, 123, 456), 123);
    assert_eq!(ct_select_u64(false, 123, 456), 456);
}

#[test]
fn test_ct_conditional_swap() {
    let mut a = [0u8; 32];
    let mut b = [0xFFu8; 32];

    ct_conditional_swap_32(&mut a, &mut b, false);
    assert_eq!(a, [0u8; 32]);
    assert_eq!(b, [0xFFu8; 32]);

    ct_conditional_swap_32(&mut a, &mut b, true);
    assert_eq!(a, [0xFFu8; 32]);
    assert_eq!(b, [0u8; 32]);
}

#[test]
fn test_ct_lookup() {
    let table: [u8; 256] = core::array::from_fn(|i| i as u8);
    for i in 0..=255 {
        assert_eq!(ct_lookup_u8(&table, i), i);
    }
}

#[test]
fn test_ct_arithmetic() {
    let (sum, carry) = ct_add_u64(u64::MAX, 1);
    assert_eq!(sum, 0);
    assert_eq!(carry, 1);

    let (diff, borrow) = ct_sub_u64(0, 1);
    assert_eq!(diff, u64::MAX);
    assert_eq!(borrow, 1);
}

#[test]
fn test_ct_clz_u64() {
    assert_eq!(ct_clz_u64(0), 64);
    assert_eq!(ct_clz_u64(u64::MAX), 0);
    assert_eq!(ct_clz_u64(1), 63);
    assert_eq!(ct_clz_u64(2), 62);
    assert_eq!(ct_clz_u64(4), 61);
    assert_eq!(ct_clz_u64(1 << 31), 32);
    assert_eq!(ct_clz_u64(1 << 63), 0);
    assert_eq!(ct_clz_u64(0x0000_0000_0000_00FF), 56);
    assert_eq!(ct_clz_u64(0x0000_0000_0000_FFFF), 48);
    assert_eq!(ct_clz_u64(0x0000_0000_FFFF_FFFF), 32);
    assert_eq!(ct_clz_u64(0x0000_FFFF_FFFF_FFFF), 16);
    assert_eq!(ct_clz_u64(0x00FF_FFFF_FFFF_FFFF), 8);
}

#[test]
fn test_secure_zero() {
    let mut data = [0xAAu8; 32];
    secure_zero(&mut data);
    assert!(ct_is_zero_slice(&data));
}

#[test]
fn test_ct_is_zero_slice() {
    assert!(ct_is_zero_slice(&[0u8; 16]));
    assert!(!ct_is_zero_slice(&[0, 0, 0, 1]));
    assert!(!ct_is_zero_slice(&[1, 0, 0, 0]));
}
