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
use alloc::vec;
use alloc::vec::Vec;

fn test_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[test]
fn test_empty() {
    let hash = blake3_hash(&[]);
    let expected = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_1_byte() {
    let input = test_input(1);
    let hash = blake3_hash(&input);
    let expected = [
        0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1,
        0x4c, 0x88, 0x6e, 0x35, 0xaf, 0xa0, 0x36, 0x73,
        0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1,
        0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92, 0xe2, 0x13,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_2_bytes() {
    let input = test_input(2);
    let hash = blake3_hash(&input);
    let expected = [
        0x7b, 0x70, 0x15, 0xbb, 0x92, 0xcf, 0x0b, 0x31,
        0x80, 0x37, 0x70, 0x2a, 0x6c, 0xdd, 0x81, 0xde,
        0xe4, 0x12, 0x24, 0xf7, 0x34, 0x68, 0x4c, 0x2c,
        0x12, 0x2c, 0xd6, 0x35, 0x9c, 0xb1, 0xee, 0x63,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_3_bytes() {
    let input = test_input(3);
    let hash = blake3_hash(&input);
    let expected = [
        0xe1, 0xbe, 0x4d, 0x7a, 0x8a, 0xb5, 0x56, 0x0a,
        0xa4, 0x19, 0x9e, 0xea, 0x33, 0x98, 0x49, 0xba,
        0x8e, 0x29, 0x3d, 0x55, 0xca, 0x0a, 0x81, 0x00,
        0x67, 0x26, 0xd1, 0x84, 0x51, 0x9e, 0x64, 0x7f,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_1023_bytes() {
    let input = test_input(1023);
    let hash = blake3_hash(&input);
    let expected = [
        0x10, 0x10, 0x89, 0x70, 0xee, 0xda, 0x3e, 0xb9,
        0x32, 0xba, 0xac, 0x14, 0x28, 0xc7, 0xa2, 0x16,
        0x3b, 0x0e, 0x92, 0x4c, 0x9a, 0x9e, 0x25, 0xb3,
        0x5b, 0xba, 0x72, 0xb2, 0x8f, 0x70, 0xbd, 0x11,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_1024_bytes() {
    let input = test_input(1024);
    let hash = blake3_hash(&input);
    let expected = [
        0x42, 0x21, 0x47, 0x39, 0xf0, 0x95, 0xa4, 0x06,
        0xf3, 0xfc, 0x83, 0xde, 0xb8, 0x89, 0x74, 0x4a,
        0xc0, 0x0d, 0xf8, 0x31, 0xc1, 0x0d, 0xaa, 0x55,
        0x18, 0x9b, 0x5d, 0x12, 0x1c, 0x85, 0x5a, 0xf7,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_1025_bytes() {
    let input = test_input(1025);
    let hash = blake3_hash(&input);
    let expected = [
        0xd0, 0x02, 0x78, 0xae, 0x47, 0xeb, 0x27, 0xb3,
        0x4f, 0xae, 0xcf, 0x67, 0xb4, 0xfe, 0x26, 0x3f,
        0x82, 0xd5, 0x41, 0x29, 0x16, 0xc1, 0xff, 0xd9,
        0x7c, 0x8c, 0xb7, 0xfb, 0x81, 0x4b, 0x84, 0x44,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_2048_bytes() {
    let input = test_input(2048);
    let hash = blake3_hash(&input);
    let expected = [
        0xe7, 0x76, 0xb6, 0x02, 0x8c, 0x7c, 0xd2, 0x2a,
        0x4d, 0x0b, 0xa1, 0x82, 0xa8, 0xbf, 0x62, 0x20,
        0x5d, 0x2e, 0xf5, 0x76, 0x46, 0x7e, 0x83, 0x8e,
        0xd6, 0xf2, 0x52, 0x9b, 0x85, 0xfb, 0xa2, 0x4a,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_8192_bytes() {
    let input = test_input(8192);
    let hash = blake3_hash(&input);
    let expected = [
        0xaa, 0xe7, 0x92, 0x48, 0x4c, 0x8e, 0xfe, 0x4f,
        0x19, 0xe2, 0xca, 0x7d, 0x37, 0x1d, 0x8c, 0x46,
        0x7f, 0xfb, 0x10, 0x74, 0x8d, 0x8a, 0x5a, 0x1a,
        0xe5, 0x79, 0x94, 0x8f, 0x71, 0x8a, 0x2a, 0x63,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_31744_bytes() {
    let input = test_input(31744);
    let hash = blake3_hash(&input);
    let expected = [
        0x62, 0xb6, 0x96, 0x0e, 0x1a, 0x44, 0xbc, 0xc1,
        0xeb, 0x1a, 0x61, 0x1a, 0x8d, 0x62, 0x35, 0xb6,
        0xb4, 0xb7, 0x8f, 0x32, 0xe7, 0xab, 0xc4, 0xfb,
        0x4c, 0x6c, 0xdc, 0xce, 0x94, 0x89, 0x5c, 0x47,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_incremental_single() {
    let input = test_input(1024);
    let mut hasher = Hasher::new();
    hasher.update(&input);
    let hash1 = hasher.finalize();
    let hash2 = blake3_hash(&input);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_incremental_chunks() {
    let input = test_input(4096);
    let mut hasher = Hasher::new();

    hasher.update(&input[0..100]);
    hasher.update(&input[100..1000]);
    hasher.update(&input[1000..1024]);
    hasher.update(&input[1024..2048]);
    hasher.update(&input[2048..4096]);

    let hash1 = hasher.finalize();
    let hash2 = blake3_hash(&input);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_incremental_byte_by_byte() {
    let input = test_input(256);
    let mut hasher = Hasher::new();
    for &byte in &input {
        hasher.update(&[byte]);
    }
    let hash1 = hasher.finalize();
    let hash2 = blake3_hash(&input);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_keyed_hash_empty() {
    let key = [0u8; 32];
    let hash = blake3_keyed_hash(&key, &[]);
    let unkeyed = blake3_hash(&[]);
    assert_ne!(hash, unkeyed);
}

#[test]
fn test_keyed_hash_official() {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let input = test_input(1);
    let hash = blake3_keyed_hash(&key, &input);
    let expected = [
        0xd0, 0x8b, 0x45, 0xc6, 0xb1, 0x27, 0xee, 0x94,
        0xf3, 0xf8, 0x52, 0x7a, 0x0b, 0x82, 0xa5, 0xf8,
        0x0b, 0xe1, 0x69, 0x5a, 0x0e, 0xae, 0xc6, 0x02,
        0x2e, 0x77, 0x2c, 0x0e, 0xb9, 0x5a, 0x7e, 0x8b,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_derive_key_official() {
    let context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    let input = test_input(1);
    let mut output = [0u8; 32];
    blake3_derive_key(context, &input, &mut output);
    let expected = [
        0xb3, 0xe2, 0xe3, 0x40, 0xa1, 0x17, 0xa4, 0x99,
        0xc6, 0xcf, 0x23, 0x98, 0xa1, 0x9e, 0xe0, 0xd2,
        0x9c, 0xca, 0x2b, 0xb7, 0x40, 0x4c, 0x73, 0x06,
        0x33, 0x82, 0x69, 0x3b, 0xf6, 0x6c, 0xb0, 0x6c,
    ];
    assert_eq!(output, expected);
}

#[test]
fn test_xof_extended() {
    let input = test_input(1);
    let mut hasher = Hasher::new();
    hasher.update(&input);

    let mut output = [0u8; 64];
    hasher.finalize_xof().fill(&mut output);

    let hash = blake3_hash(&input);
    assert_eq!(&output[..32], &hash);
}

#[test]
fn test_xof_incremental() {
    let input = test_input(100);
    let mut hasher = Hasher::new();
    hasher.update(&input);

    let mut reader = hasher.finalize_xof();

    let mut out1 = [0u8; 10];
    let mut out2 = [0u8; 22];
    let mut out3 = [0u8; 32];
    reader.fill(&mut out1);
    reader.fill(&mut out2);
    reader.fill(&mut out3);

    let mut hasher2 = Hasher::new();
    hasher2.update(&input);
    let mut all = [0u8; 64];
    hasher2.finalize_xof().fill(&mut all);

    assert_eq!(&out1, &all[0..10]);
    assert_eq!(&out2, &all[10..32]);
    assert_eq!(&out3, &all[32..64]);
}

#[test]
fn test_reset() {
    let input1 = test_input(100);
    let input2 = test_input(200);

    let mut hasher = Hasher::new();
    hasher.update(&input1);
    let hash1 = hasher.finalize();

    hasher.reset();
    hasher.update(&input2);
    let hash2 = hasher.finalize();

    assert_eq!(hash2, blake3_hash(&input2));
    assert_ne!(hash1, hash2);
}

#[test]
fn test_chunk_boundary() {
    let input = test_input(CHUNK_LEN);
    let hash = blake3_hash(&input);

    let mut hasher = Hasher::new();
    hasher.update(&input[..512]);
    hasher.update(&input[512..]);
    assert_eq!(hash, hasher.finalize());
}

#[test]
fn test_block_boundary() {
    let input = test_input(BLOCK_LEN);
    let hash = blake3_hash(&input);

    let mut hasher = Hasher::new();
    hasher.update(&input[..32]);
    hasher.update(&input[32..]);
    assert_eq!(hash, hasher.finalize());
}

#[test]
fn test_large_input() {
    let input = test_input(100_000);
    let hash = blake3_hash(&input);

    let mut hasher = Hasher::new();
    for chunk in input.chunks(1337) {
        hasher.update(chunk);
    }
    assert_eq!(hash, hasher.finalize());
}
