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

use super::aead::{Aes256Gcm, aes256_gcm_encrypt, aes256_gcm_decrypt};
use super::ghash::gf128_mul_bitwise;

#[test]
fn test_nist_case_13_empty() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt: &[u8] = &[];

    let expected_tag: [u8; 16] = [
        0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
        0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
    ];

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), 16);
    assert_eq!(&ct[..], &expected_tag[..], "Tag mismatch for NIST Test Case 13");

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec.len(), 0);
}

#[test]
fn test_nist_case_14_one_block() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt = [0u8; 16];

    let expected_ct: [u8; 16] = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    ];
    let expected_tag: [u8; 16] = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    ];

    let result = aes256_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    assert_eq!(result.len(), 32);

    let ct = &result[..16];
    let tag = &result[16..];
    assert_eq!(ct, &expected_ct[..], "Ciphertext mismatch for NIST Test Case 14");
    assert_eq!(tag, &expected_tag[..], "Tag mismatch for NIST Test Case 14");

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &result).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn test_nist_case_16_with_aad() {
    let key: [u8; 32] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];
    let nonce: [u8; 12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];
    let aad: [u8; 20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2,
    ];
    let pt: [u8; 60] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39,
    ];

    let expected_ct: [u8; 60] = [
        0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
        0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
        0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
        0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
        0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
        0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
        0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
        0xbc, 0xc9, 0xf6, 0x62,
    ];
    let expected_tag: [u8; 16] = [
        0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
        0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
    ];

    let result = aes256_gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
    assert_eq!(result.len(), 76);

    let ct = &result[..60];
    let tag = &result[60..];
    assert_eq!(ct, &expected_ct[..], "Ciphertext mismatch for NIST Test Case 16");
    assert_eq!(tag, &expected_tag[..], "Tag mismatch for NIST Test Case 16");

    let dec = aes256_gcm_decrypt(&key, &nonce, &aad, &result).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn test_with_aad() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"additional authenticated data";
    let pt = b"secret message to encrypt";

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
    assert_eq!(ct.len(), pt.len() + 16);

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);

    let bad_aad = b"modified authenticated data!!";
    let result = aes256_gcm_decrypt(&key, &nonce, bad_aad, &ct);
    assert!(result.is_err());

    let mut bad_ct = ct.clone();
    bad_ct[0] ^= 1;
    let result = aes256_gcm_decrypt(&key, &nonce, aad, &bad_ct);
    assert!(result.is_err());

    let mut bad_tag = ct.clone();
    let tag_start = bad_tag.len() - 16;
    bad_tag[tag_start] ^= 1;
    let result = aes256_gcm_decrypt(&key, &nonce, aad, &bad_tag);
    assert!(result.is_err());
}

#[test]
fn test_large_plaintext() {
    let key = [0xABu8; 32];
    let nonce = [0xCDu8; 12];
    let aad = b"header";
    let pt: Vec<u8> = (0..1000).map(|i| i as u8).collect();

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    assert_eq!(ct.len(), pt.len() + 16);

    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn test_in_place() {
    let key = [0x12u8; 32];
    let nonce = [0x34u8; 12];
    let aad = b"aad";
    let original = b"plaintext data here";

    let gcm = Aes256Gcm::new(&key);

    let mut buffer = original.to_vec();
    let tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);

    assert_ne!(&buffer[..], original);

    gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).unwrap();
    assert_eq!(&buffer[..], original);
}

#[test]
fn test_gf128_mul() {
    let zero = (0u64, 0u64);
    let x = (0x1234567890ABCDEFu64, 0xFEDCBA0987654321u64);
    assert_eq!(gf128_mul_bitwise(zero, x), zero);
    assert_eq!(gf128_mul_bitwise(x, zero), zero);

    let one = (0x8000_0000_0000_0000u64, 0u64);
    let y = (0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64);
    assert_eq!(gf128_mul_bitwise(one, y), y);
}

#[test]
fn test_nonce_affects_tag() {
    let key = [0x55u8; 32];
    let nonce1 = [0x00u8; 12];
    let nonce2 = [0x01u8; 12];
    let aad = b"same aad";
    let pt = b"same plaintext";

    let ct1 = aes256_gcm_encrypt(&key, &nonce1, aad, pt).unwrap();
    let ct2 = aes256_gcm_encrypt(&key, &nonce2, aad, pt).unwrap();

    assert_ne!(ct1, ct2);

    assert_eq!(aes256_gcm_decrypt(&key, &nonce1, aad, &ct1).unwrap(), pt);
    assert_eq!(aes256_gcm_decrypt(&key, &nonce2, aad, &ct2).unwrap(), pt);

    assert!(aes256_gcm_decrypt(&key, &nonce1, aad, &ct2).is_err());
    assert!(aes256_gcm_decrypt(&key, &nonce2, aad, &ct1).is_err());
}

#[test]
fn test_one_block() {
    let key = [0x77u8; 32];
    let nonce = [0x88u8; 12];
    let aad: &[u8] = &[];
    let pt = [0x99u8; 16];

    let ct = aes256_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
    let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn test_partial_block() {
    let key = [0xAAu8; 32];
    let nonce = [0xBBu8; 12];
    let aad = [0xCCu8; 7];
    let pt = [0xDDu8; 13];

    let ct = aes256_gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
    let dec = aes256_gcm_decrypt(&key, &nonce, &aad, &ct).unwrap();
    assert_eq!(dec, pt);
}

#[test]
fn test_truncated_ciphertext() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    let result = aes256_gcm_decrypt(&key, &nonce, &[], &[0u8; 15]);
    assert!(result.is_err());
}
