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
use super::core::{SBOX, INV_SBOX, gf_mul};
use super::modes::increment_be128;
use crate::crypto::constant_time::ct_lookup_u8;
use alloc::vec::Vec;

#[test]
fn test_aes256_nist_sp800_38a() {
    let key: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    ];
    let plaintext: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    ];
    let expected_ct: [u8; 16] = [
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    ];

    let aes = Aes256::new(&key);
    let ciphertext = aes.encrypt_block(&plaintext);
    assert_eq!(ciphertext, expected_ct);

    let decrypted = aes.decrypt_block(&ciphertext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes256_fips197_appendix_c3() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let expected_ct: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ];

    let aes = Aes256::new(&key);
    let ciphertext = aes.encrypt_block(&plaintext);
    assert_eq!(ciphertext, expected_ct);

    let decrypted = aes.decrypt_block(&ciphertext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes256_zero_key_plaintext() {
    let key = [0u8; 32];
    let plaintext = [0u8; 16];

    let aes = Aes256::new(&key);
    let ciphertext = aes.encrypt_block(&plaintext);

    assert_ne!(ciphertext, [0u8; 16]);

    let decrypted = aes.decrypt_block(&ciphertext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes256_ctr_roundtrip() {
    let key = [0x42u8; 32];
    let mut ctr = [0u8; 16];
    ctr[15] = 1;

    let original: Vec<u8> = (0..100).collect();
    let mut data = original.clone();

    let aes = Aes256::new(&key);
    aes.ctr_apply(&mut ctr.clone(), &mut data);

    assert_ne!(data, original);

    let mut ctr2 = [0u8; 16];
    ctr2[15] = 1;
    aes.ctr_apply(&mut ctr2, &mut data);

    assert_eq!(data, original);
}

#[test]
fn test_aes128_nist_sp800_38a() {
    let key: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let plaintext: [u8; 16] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    ];
    let expected_ct: [u8; 16] = [
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    ];

    let aes = Aes128::new(&key);
    let ciphertext = aes.encrypt_block(&plaintext);
    assert_eq!(ciphertext, expected_ct);

    let decrypted = aes.decrypt_block(&ciphertext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes128_fips197_appendix_c1() {
    let key: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let plaintext: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let expected_ct: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ];

    let aes = Aes128::new(&key);
    let ciphertext = aes.encrypt_block(&plaintext);
    assert_eq!(ciphertext, expected_ct);

    let decrypted = aes.decrypt_block(&ciphertext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_aes128_ctr_roundtrip() {
    let key = [0x55u8; 16];
    let mut ctr = [0u8; 16];
    ctr[15] = 1;

    let original: Vec<u8> = (0..64).collect();
    let mut data = original.clone();

    let aes = Aes128::new(&key);
    aes.ctr_apply(&mut ctr.clone(), &mut data);

    let mut ctr2 = [0u8; 16];
    ctr2[15] = 1;
    aes.ctr_apply(&mut ctr2, &mut data);

    assert_eq!(data, original);
}

#[test]
fn test_gf_mul_identity() {
    for a in 0..=255u8 {
        assert_eq!(gf_mul(a, 1), a);
        assert_eq!(gf_mul(1, a), a);
    }
}

#[test]
fn test_gf_mul_zero() {
    for a in 0..=255u8 {
        assert_eq!(gf_mul(a, 0), 0);
        assert_eq!(gf_mul(0, a), 0);
    }
}

#[test]
fn test_gf_mul_known_values() {
    assert_eq!(gf_mul(0x57, 0x83), 0xc1);
    assert_eq!(gf_mul(0x57, 0x02), 0xae);
    assert_eq!(gf_mul(0x57, 0x04), 0x47);
}

#[test]
fn test_gf_mul_commutative() {
    let test_values = [0x00, 0x01, 0x02, 0x03, 0x53, 0xCA, 0xFE, 0xFF];
    for &a in &test_values {
        for &b in &test_values {
            assert_eq!(gf_mul(a, b), gf_mul(b, a));
        }
    }
}

#[test]
fn test_sbox_inverse() {
    for i in 0..=255u8 {
        let s = ct_lookup_u8(&SBOX, i);
        let inv = ct_lookup_u8(&INV_SBOX, s);
        assert_eq!(inv, i, "INV_SBOX[SBOX[{}]] != {}", i, i);
    }
}

#[test]
fn test_sbox_known_values() {
    assert_eq!(SBOX[0x00], 0x63);
    assert_eq!(SBOX[0x01], 0x7c);
    assert_eq!(SBOX[0x53], 0xed);
    assert_eq!(SBOX[0xff], 0x16);
}

#[test]
fn test_ctr_empty_data() {
    let key = [0u8; 32];
    let mut ctr = [0u8; 16];
    let mut data: [u8; 0] = [];

    let aes = Aes256::new(&key);
    aes.ctr_apply(&mut ctr, &mut data);

    assert_eq!(ctr, [0u8; 16]);
}

#[test]
fn test_ctr_single_byte() {
    let key = [0u8; 32];
    let mut ctr = [0u8; 16];
    ctr[15] = 1;
    let mut data = [0x42u8];

    let aes = Aes256::new(&key);
    aes.ctr_apply(&mut ctr.clone(), &mut data);

    assert_ne!(data[0], 0x42);

    let mut ctr2 = [0u8; 16];
    ctr2[15] = 1;
    aes.ctr_apply(&mut ctr2, &mut data);
    assert_eq!(data[0], 0x42);
}

#[test]
fn test_counter_increment() {
    let mut ctr = [0xffu8; 16];
    increment_be128(&mut ctr);
    assert_eq!(ctr, [0u8; 16]);
}
