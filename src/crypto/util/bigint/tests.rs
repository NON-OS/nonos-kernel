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

extern crate alloc;

use alloc::format;

use super::BigUint;

#[test]
fn test_zero() {
    let z = BigUint::zero();
    assert!(z.is_zero());
    assert!(!z.is_one());
    assert_eq!(z.bits(), 0);
}

#[test]
fn test_one() {
    let one = BigUint::one();
    assert!(!one.is_zero());
    assert!(one.is_one());
    assert_eq!(one.bits(), 1);
}

#[test]
fn test_from_u64() {
    let n = BigUint::from_u64(0x123456789ABCDEF0);
    assert_eq!(n.limbs.len(), 1);
    assert_eq!(n.limbs[0], 0x123456789ABCDEF0);
}

#[test]
fn test_from_u128() {
    let n = BigUint::from_u128(0x123456789ABCDEF0_FEDCBA9876543210);
    assert_eq!(n.limbs.len(), 2);
    assert_eq!(n.limbs[0], 0xFEDCBA9876543210);
    assert_eq!(n.limbs[1], 0x123456789ABCDEF0);
}

#[test]
fn test_from_bytes_be() {
    let n = BigUint::from_bytes_be(&[0x12, 0x34, 0x56, 0x78]);
    assert_eq!(n.limbs[0], 0x12345678);

    let n = BigUint::from_bytes_be(&[0x00, 0x00, 0x12, 0x34]);
    assert_eq!(n.limbs[0], 0x1234);

    let n = BigUint::from_bytes_be(&[]);
    assert!(n.is_zero());
}

#[test]
fn test_from_bytes_le() {
    let n = BigUint::from_bytes_le(&[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(n.limbs[0], 0x12345678);
}

#[test]
fn test_bytes_roundtrip() {
    let original = BigUint::from_u128(0x123456789ABCDEF0_FEDCBA9876543210);
    let bytes_be = original.to_bytes_be();
    let restored_be = BigUint::from_bytes_be(&bytes_be);
    assert_eq!(original, restored_be);

    let bytes_le = original.to_bytes_le();
    let restored_le = BigUint::from_bytes_le(&bytes_le);
    assert_eq!(original, restored_le);
}

#[test]
fn test_from_hex() {
    let n = BigUint::from_hex("0x1234ABCD").unwrap();
    assert_eq!(n.limbs[0], 0x1234ABCD);

    let n = BigUint::from_hex("DEADBEEF").unwrap();
    assert_eq!(n.limbs[0], 0xDEADBEEF);

    let n = BigUint::from_hex("0").unwrap();
    assert!(n.is_zero());

    assert!(BigUint::from_hex("GHIJ").is_none());
}

#[test]
fn test_add() {
    let a = BigUint::from_u64(100);
    let b = BigUint::from_u64(200);
    let c = &a + &b;
    assert_eq!(c.limbs[0], 300);

    let a = BigUint::from_u64(u64::MAX);
    let b = BigUint::from_u64(1);
    let c = &a + &b;
    assert_eq!(c.limbs.len(), 2);
    assert_eq!(c.limbs[0], 0);
    assert_eq!(c.limbs[1], 1);
}

#[test]
fn test_sub() {
    let a = BigUint::from_u64(300);
    let b = BigUint::from_u64(100);
    let c = &a - &b;
    assert_eq!(c.limbs[0], 200);

    let a = BigUint::from_u128(1u128 << 64);
    let b = BigUint::from_u64(1);
    let c = &a - &b;
    assert_eq!(c.limbs[0], u64::MAX);
    assert_eq!(c.limbs.len(), 1);
}

#[test]
fn test_mul() {
    let a = BigUint::from_u64(12345);
    let b = BigUint::from_u64(67890);
    let c = &a * &b;
    assert_eq!(c.limbs[0], 12345u64 * 67890);

    let a = BigUint::from_u64(u64::MAX);
    let b = BigUint::from_u64(u64::MAX);
    let c = &a * &b;
    let expected = BigUint::from_u128((u64::MAX as u128) * (u64::MAX as u128));
    assert_eq!(c, expected);
}

#[test]
fn test_div_rem() {
    let a = BigUint::from_u64(1000);
    let b = BigUint::from_u64(7);
    let (q, r) = a.div_rem(&b).unwrap();
    assert_eq!(q.limbs[0], 142);
    assert_eq!(r.limbs[0], 6);

    let check = &(&q * &b) + &r;
    assert_eq!(a, check);
}

#[test]
fn test_div_rem_large() {
    let a = BigUint::from_u128(0x123456789ABCDEF0_0000000000000000);
    let b = BigUint::from_u64(0x12345678);
    let (q, r) = a.div_rem(&b).unwrap();

    let check = &(&q * &b) + &r;
    assert_eq!(a, check);
}

#[test]
fn test_bits() {
    assert_eq!(BigUint::zero().bits(), 0);
    assert_eq!(BigUint::one().bits(), 1);
    assert_eq!(BigUint::from_u64(255).bits(), 8);
    assert_eq!(BigUint::from_u64(256).bits(), 9);
}

#[test]
fn test_shift_left() {
    let n = BigUint::from_u64(1);
    let shifted = n.shl_bits(64);
    assert_eq!(shifted.limbs.len(), 2);
    assert_eq!(shifted.limbs[0], 0);
    assert_eq!(shifted.limbs[1], 1);

    let n = BigUint::from_u64(0b1010);
    let shifted = n.shl_bits(3);
    assert_eq!(shifted.limbs[0], 0b1010000);
}

#[test]
fn test_shift_right() {
    let n = BigUint::from_u128(1u128 << 64);
    let shifted = n.shr_bits(64);
    assert_eq!(shifted.limbs.len(), 1);
    assert_eq!(shifted.limbs[0], 1);

    let n = BigUint::from_u64(0b1010000);
    let shifted = n.shr_bits(3);
    assert_eq!(shifted.limbs[0], 0b1010);
}

#[test]
fn test_bit_get_set() {
    let mut n = BigUint::zero();
    n.set_bit(0, true);
    assert!(n.bit(0));
    assert_eq!(n.limbs[0], 1);

    n.set_bit(63, true);
    assert!(n.bit(63));
    assert_eq!(n.limbs[0], (1u64 << 63) | 1);

    n.set_bit(64, true);
    assert!(n.bit(64));
    assert_eq!(n.limbs.len(), 2);
}

#[test]
fn test_mod_pow() {
    let base = BigUint::from_u64(3);
    let exp = BigUint::from_u64(10);
    let modulus = BigUint::from_u64(7);
    let result = base.mod_pow(&exp, &modulus).unwrap();
    assert_eq!(result.limbs[0], 4);

    let two = BigUint::from_u64(2);
    let exp = BigUint::from_u64(256);
    let m = BigUint::one().shl_bits(256).sub_u64(1).unwrap();
    let result = two.mod_pow(&exp, &m).unwrap();
    assert!(result.is_one());

    let zero = BigUint::zero();
    assert!(base.mod_pow(&exp, &zero).is_none());
}

#[test]
fn test_mod_inverse() {
    let a = BigUint::from_u64(3);
    let m = BigUint::from_u64(7);
    let inv = a.mod_inverse(&m).unwrap();
    assert_eq!(inv.limbs[0], 5);

    let product = (&a * &inv) % &m;
    assert!(product.is_one());
}

#[test]
fn test_mod_inverse_no_inverse() {
    let a = BigUint::from_u64(4);
    let m = BigUint::from_u64(8);
    assert!(a.mod_inverse(&m).is_none());
}

#[test]
fn test_gcd() {
    let a = BigUint::from_u64(48);
    let b = BigUint::from_u64(18);
    let g = a.gcd(&b);
    assert_eq!(g.limbs[0], 6);

    let a = BigUint::from_u64(17);
    let b = BigUint::from_u64(13);
    let g = a.gcd(&b);
    assert!(g.is_one());
}

#[test]
fn test_is_prime_small() {
    assert!(!BigUint::from_u64(0).is_probably_prime(10));
    assert!(!BigUint::from_u64(1).is_probably_prime(10));
    assert!(BigUint::from_u64(2).is_probably_prime(10));
    assert!(BigUint::from_u64(3).is_probably_prime(10));
    assert!(!BigUint::from_u64(4).is_probably_prime(10));
    assert!(BigUint::from_u64(5).is_probably_prime(10));
    assert!(BigUint::from_u64(7).is_probably_prime(10));
    assert!(!BigUint::from_u64(9).is_probably_prime(10));
    assert!(BigUint::from_u64(11).is_probably_prime(10));
}

#[test]
fn test_is_prime_larger() {
    let m61 = BigUint::from_u64((1u64 << 61) - 1);
    assert!(m61.is_probably_prime(20));

    let not_prime = BigUint::from_u64((1u64 << 61) - 3);
    assert!(!not_prime.is_probably_prime(20));
}

#[test]
fn test_comparison() {
    let a = BigUint::from_u64(100);
    let b = BigUint::from_u64(200);

    assert!(a < b);
    assert!(b > a);
    assert!(a <= a);
    assert!(a >= a);
    assert!(a == a);
    assert!(a != b);
}

#[test]
fn test_ct_eq() {
    let a = BigUint::from_u64(12345);
    let b = BigUint::from_u64(12345);
    let c = BigUint::from_u64(12346);

    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
}

#[test]
fn test_display() {
    assert_eq!(format!("{}", BigUint::zero()), "0");
    assert_eq!(format!("{}", BigUint::from_u64(12345)), "12345");
}

#[test]
fn test_hex_display() {
    let n = BigUint::from_u64(0xDEADBEEF);
    assert_eq!(n.to_hex(), "deadbeef");
}
