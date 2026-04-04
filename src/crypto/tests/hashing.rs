// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::crypto::hash::{
    blake3_hash, blake3_keyed_hash, blake3_derive_key, blake3_hash_xof,
    sha3_256, sha3_512, shake128, shake256, keccak256,
    sha512, sha512_hash,
    sha256, hmac_sha256, hmac_verify, hkdf_expand, ripemd160,
};

#[test]
fn test_blake3_empty() {
    let hash = blake3_hash(b"");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_blake3_abc() {
    let hash = blake3_hash(b"abc");
    assert_eq!(hash.len(), 32);
    assert_ne!(hash, [0u8; 32]);
}

#[test]
fn test_blake3_deterministic() {
    let hash1 = blake3_hash(b"test data");
    let hash2 = blake3_hash(b"test data");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_different_inputs() {
    let hash1 = blake3_hash(b"hello");
    let hash2 = blake3_hash(b"world");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_blake3_keyed() {
    let key = [0x42u8; 32];
    let hash = blake3_keyed_hash(&key, b"message");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_blake3_keyed_deterministic() {
    let key = [0x42u8; 32];
    let hash1 = blake3_keyed_hash(&key, b"message");
    let hash2 = blake3_keyed_hash(&key, b"message");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_keyed_different_keys() {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let hash1 = blake3_keyed_hash(&key1, b"message");
    let hash2 = blake3_keyed_hash(&key2, b"message");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_blake3_derive_key() {
    let context = "NONOS test context";
    let material = b"key material";
    let derived = blake3_derive_key(context, material);
    assert_eq!(derived.len(), 32);
}

#[test]
fn test_blake3_derive_key_deterministic() {
    let context = "NONOS test context";
    let material = b"key material";
    let derived1 = blake3_derive_key(context, material);
    let derived2 = blake3_derive_key(context, material);
    assert_eq!(derived1, derived2);
}

#[test]
fn test_blake3_xof() {
    let mut output = [0u8; 64];
    blake3_hash_xof(b"input", &mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_blake3_xof_128_bytes() {
    let mut output = [0u8; 128];
    blake3_hash_xof(b"input", &mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_sha3_256_empty() {
    let hash = sha3_256(b"");
    let expected = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
        0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
        0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_sha3_256_abc() {
    let hash = sha3_256(b"abc");
    let expected = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
        0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
        0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
        0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_sha3_256_deterministic() {
    let hash1 = sha3_256(b"test");
    let hash2 = sha3_256(b"test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_sha3_512_empty() {
    let hash = sha3_512(b"");
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_sha3_512_abc() {
    let hash = sha3_512(b"abc");
    assert_eq!(hash.len(), 64);
    assert_ne!(hash, [0u8; 64]);
}

#[test]
fn test_sha3_512_deterministic() {
    let hash1 = sha3_512(b"test");
    let hash2 = sha3_512(b"test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_sha3_256_vs_512_different() {
    let h256 = sha3_256(b"test");
    let h512 = sha3_512(b"test");
    assert_ne!(&h256[..], &h512[..32]);
}

#[test]
fn test_shake128_basic() {
    let mut output = [0u8; 32];
    shake128(b"input", &mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_shake128_variable_output() {
    let mut out32 = [0u8; 32];
    let mut out64 = [0u8; 64];
    shake128(b"input", &mut out32);
    shake128(b"input", &mut out64);
    assert_eq!(&out32[..], &out64[..32]);
}

#[test]
fn test_shake256_basic() {
    let mut output = [0u8; 32];
    shake256(b"input", &mut output);
    assert!(output.iter().any(|&b| b != 0));
}

#[test]
fn test_shake256_variable_output() {
    let mut out32 = [0u8; 32];
    let mut out64 = [0u8; 64];
    shake256(b"input", &mut out32);
    shake256(b"input", &mut out64);
    assert_eq!(&out32[..], &out64[..32]);
}

#[test]
fn test_keccak256_empty() {
    let hash = keccak256(b"");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_keccak256_deterministic() {
    let hash1 = keccak256(b"ethereum");
    let hash2 = keccak256(b"ethereum");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_keccak256_vs_sha3_256_different() {
    let k = keccak256(b"test");
    let s = sha3_256(b"test");
    assert_ne!(k, s);
}

#[test]
fn test_sha512_empty() {
    let hash = sha512(b"");
    assert_eq!(hash.len(), 64);
}

#[test]
fn test_sha512_abc() {
    let hash = sha512(b"abc");
    assert_eq!(hash.len(), 64);
    assert_ne!(hash, [0u8; 64]);
}

#[test]
fn test_sha512_deterministic() {
    let hash1 = sha512(b"test");
    let hash2 = sha512(b"test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_sha512_hash_struct() {
    let hash = sha512_hash(b"test");
    assert_eq!(hash.as_bytes().len(), 64);
}

#[test]
fn test_sha256_empty() {
    let hash = sha256(b"");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_sha256_abc() {
    let hash = sha256(b"abc");
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ];
    assert_eq!(hash, expected);
}

#[test]
fn test_sha256_deterministic() {
    let hash1 = sha256(b"test");
    let hash2 = sha256(b"test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_hmac_sha256_basic() {
    let key = b"secret key";
    let message = b"message";
    let mac = hmac_sha256(key, message);
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_hmac_sha256_deterministic() {
    let key = b"secret key";
    let message = b"message";
    let mac1 = hmac_sha256(key, message);
    let mac2 = hmac_sha256(key, message);
    assert_eq!(mac1, mac2);
}

#[test]
fn test_hmac_sha256_different_keys() {
    let message = b"message";
    let mac1 = hmac_sha256(b"key1", message);
    let mac2 = hmac_sha256(b"key2", message);
    assert_ne!(mac1, mac2);
}

#[test]
fn test_hmac_sha256_different_messages() {
    let key = b"secret key";
    let mac1 = hmac_sha256(key, b"message1");
    let mac2 = hmac_sha256(key, b"message2");
    assert_ne!(mac1, mac2);
}

#[test]
fn test_hmac_verify_valid() {
    let key = b"secret key";
    let message = b"message";
    let mac = hmac_sha256(key, message);
    assert!(hmac_verify(key, message, &mac));
}

#[test]
fn test_hmac_verify_invalid_mac() {
    let key = b"secret key";
    let message = b"message";
    let mut mac = hmac_sha256(key, message);
    mac[0] ^= 0x01;
    assert!(!hmac_verify(key, message, &mac));
}

#[test]
fn test_hmac_verify_wrong_key() {
    let message = b"message";
    let mac = hmac_sha256(b"key1", message);
    assert!(!hmac_verify(b"key2", message, &mac));
}

#[test]
fn test_hmac_verify_wrong_message() {
    let key = b"secret key";
    let mac = hmac_sha256(key, b"message1");
    assert!(!hmac_verify(key, b"message2", &mac));
}

#[test]
fn test_hkdf_expand_basic() {
    let prk = [0x42u8; 32];
    let info = b"application info";
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, info, &mut okm);
    assert!(okm.iter().any(|&b| b != 0));
}

#[test]
fn test_hkdf_expand_deterministic() {
    let prk = [0x42u8; 32];
    let info = b"application info";
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    hkdf_expand(&prk, info, &mut okm1);
    hkdf_expand(&prk, info, &mut okm2);
    assert_eq!(okm1, okm2);
}

#[test]
fn test_hkdf_expand_different_info() {
    let prk = [0x42u8; 32];
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    hkdf_expand(&prk, b"info1", &mut okm1);
    hkdf_expand(&prk, b"info2", &mut okm2);
    assert_ne!(okm1, okm2);
}

#[test]
fn test_hkdf_expand_64_bytes() {
    let prk = [0x42u8; 32];
    let info = b"application info";
    let mut okm = [0u8; 64];
    hkdf_expand(&prk, info, &mut okm);
    assert!(okm.iter().any(|&b| b != 0));
}

#[test]
fn test_ripemd160_empty() {
    let hash = ripemd160(b"");
    assert_eq!(hash.len(), 20);
}

#[test]
fn test_ripemd160_abc() {
    let hash = ripemd160(b"abc");
    assert_eq!(hash.len(), 20);
    assert_ne!(hash, [0u8; 20]);
}

#[test]
fn test_ripemd160_deterministic() {
    let hash1 = ripemd160(b"test");
    let hash2 = ripemd160(b"test");
    assert_eq!(hash1, hash2);
}

#[test]
fn test_different_hash_algorithms_different_output() {
    let input = b"test input";
    let s256 = sha256(input);
    let s512 = sha512(input);
    let b3 = blake3_hash(input);
    let sha3 = sha3_256(input);
    let k256 = keccak256(input);

    assert_ne!(&s256[..], &s512[..32]);
    assert_ne!(&s256[..], &b3[..]);
    assert_ne!(&s256[..], &sha3[..]);
    assert_ne!(&s256[..], &k256[..]);
    assert_ne!(&b3[..], &sha3[..]);
}

#[test]
fn test_large_input_hashing() {
    let large_input: [u8; 4096] = [0x42; 4096];
    let hash = sha256(&large_input);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_single_byte_inputs_all_different() {
    let hashes: [[u8; 32]; 256] = core::array::from_fn(|i| sha256(&[i as u8]));
    for i in 0..256 {
        for j in (i + 1)..256 {
            assert_ne!(hashes[i], hashes[j]);
        }
    }
}
