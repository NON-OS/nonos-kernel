// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Cryptographic hash function tests - BLAKE3, SHA-3, SHA-256/512, HMAC, HKDF, RIPEMD-160

use crate::crypto::hash::{
    blake3_derive_key, blake3_hash, blake3_hash_xof, blake3_keyed_hash, hkdf_expand, hmac_sha256,
    hmac_verify, keccak256, ripemd160, sha256, sha3_256, sha3_512, sha512, sha512_hash, shake128,
    shake256,
};
use crate::test::framework::TestResult;

pub(crate) fn test_blake3_empty() -> TestResult {
    let hash = blake3_hash(b"");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_abc() -> TestResult {
    let hash = blake3_hash(b"abc");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    if hash == [0u8; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_deterministic() -> TestResult {
    let hash1 = blake3_hash(b"test data");
    let hash2 = blake3_hash(b"test data");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_different_inputs() -> TestResult {
    let hash1 = blake3_hash(b"hello");
    let hash2 = blake3_hash(b"world");
    if hash1 == hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_keyed() -> TestResult {
    let key = [0x42u8; 32];
    let hash = blake3_keyed_hash(&key, b"message");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_keyed_deterministic() -> TestResult {
    let key = [0x42u8; 32];
    let hash1 = blake3_keyed_hash(&key, b"message");
    let hash2 = blake3_keyed_hash(&key, b"message");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_keyed_different_keys() -> TestResult {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let hash1 = blake3_keyed_hash(&key1, b"message");
    let hash2 = blake3_keyed_hash(&key2, b"message");
    if hash1 == hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_derive_key() -> TestResult {
    let context = "NONOS test context";
    let material = b"key material";
    let derived = blake3_derive_key(context, material);
    if derived.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_derive_key_deterministic() -> TestResult {
    let context = "NONOS test context";
    let material = b"key material";
    let derived1 = blake3_derive_key(context, material);
    let derived2 = blake3_derive_key(context, material);
    if derived1 != derived2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_xof() -> TestResult {
    let mut output = [0u8; 64];
    blake3_hash_xof(b"input", &mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_blake3_xof_128_bytes() -> TestResult {
    let mut output = [0u8; 128];
    blake3_hash_xof(b"input", &mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_256_empty() -> TestResult {
    let hash = sha3_256(b"");
    let expected = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6,
        0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8,
        0x43, 0x4a,
    ];
    if hash != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_256_abc() -> TestResult {
    let hash = sha3_256(b"abc");
    let expected = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    if hash != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_256_deterministic() -> TestResult {
    let hash1 = sha3_256(b"test");
    let hash2 = sha3_256(b"test");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_512_empty() -> TestResult {
    let hash = sha3_512(b"");
    if hash.len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_512_abc() -> TestResult {
    let hash = sha3_512(b"abc");
    if hash.len() != 64 {
        return TestResult::Fail;
    }
    if hash == [0u8; 64] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_512_deterministic() -> TestResult {
    let hash1 = sha3_512(b"test");
    let hash2 = sha3_512(b"test");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha3_256_vs_512_different() -> TestResult {
    let h256 = sha3_256(b"test");
    let h512 = sha3_512(b"test");
    if &h256[..] == &h512[..32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_shake128_basic() -> TestResult {
    let mut output = [0u8; 32];
    shake128(b"input", &mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_shake128_variable_output() -> TestResult {
    let mut out32 = [0u8; 32];
    let mut out64 = [0u8; 64];
    shake128(b"input", &mut out32);
    shake128(b"input", &mut out64);
    if &out32[..] != &out64[..32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_shake256_basic() -> TestResult {
    let mut output = [0u8; 32];
    shake256(b"input", &mut output);
    if !output.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_shake256_variable_output() -> TestResult {
    let mut out32 = [0u8; 32];
    let mut out64 = [0u8; 64];
    shake256(b"input", &mut out32);
    shake256(b"input", &mut out64);
    if &out32[..] != &out64[..32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keccak256_empty() -> TestResult {
    let hash = keccak256(b"");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keccak256_deterministic() -> TestResult {
    let hash1 = keccak256(b"ethereum");
    let hash2 = keccak256(b"ethereum");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keccak256_vs_sha3_256_different() -> TestResult {
    let k = keccak256(b"test");
    let s = sha3_256(b"test");
    if k == s {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha512_empty() -> TestResult {
    let hash = sha512(b"");
    if hash.len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha512_abc() -> TestResult {
    let hash = sha512(b"abc");
    if hash.len() != 64 {
        return TestResult::Fail;
    }
    if hash == [0u8; 64] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha512_deterministic() -> TestResult {
    let hash1 = sha512(b"test");
    let hash2 = sha512(b"test");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha512_hash_struct() -> TestResult {
    let hash = sha512_hash(b"test");
    if hash.as_bytes().len() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha256_empty() -> TestResult {
    let hash = sha256(b"");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha256_abc() -> TestResult {
    let hash = sha256(b"abc");
    let expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    if hash != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sha256_deterministic() -> TestResult {
    let hash1 = sha256(b"test");
    let hash2 = sha256(b"test");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_sha256_basic() -> TestResult {
    let key = b"secret key";
    let message = b"message";
    let mac = hmac_sha256(key, message);
    if mac.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_sha256_deterministic() -> TestResult {
    let key = b"secret key";
    let message = b"message";
    let mac1 = hmac_sha256(key, message);
    let mac2 = hmac_sha256(key, message);
    if mac1 != mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_sha256_different_keys() -> TestResult {
    let message = b"message";
    let mac1 = hmac_sha256(b"key1", message);
    let mac2 = hmac_sha256(b"key2", message);
    if mac1 == mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_sha256_different_messages() -> TestResult {
    let key = b"secret key";
    let mac1 = hmac_sha256(key, b"message1");
    let mac2 = hmac_sha256(key, b"message2");
    if mac1 == mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_verify_valid() -> TestResult {
    let key = b"secret key";
    let message = b"message";
    let mac = hmac_sha256(key, message);
    if !hmac_verify(key, message, &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_verify_invalid_mac() -> TestResult {
    let key = b"secret key";
    let message = b"message";
    let mut mac = hmac_sha256(key, message);
    mac[0] ^= 0x01;
    if hmac_verify(key, message, &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_verify_wrong_key() -> TestResult {
    let message = b"message";
    let mac = hmac_sha256(b"key1", message);
    if hmac_verify(b"key2", message, &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hmac_verify_wrong_message() -> TestResult {
    let key = b"secret key";
    let mac = hmac_sha256(key, b"message1");
    if hmac_verify(key, b"message2", &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hkdf_expand_basic() -> TestResult {
    let prk = [0x42u8; 32];
    let info = b"application info";
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, info, &mut okm);
    if !okm.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hkdf_expand_deterministic() -> TestResult {
    let prk = [0x42u8; 32];
    let info = b"application info";
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    hkdf_expand(&prk, info, &mut okm1);
    hkdf_expand(&prk, info, &mut okm2);
    if okm1 != okm2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hkdf_expand_different_info() -> TestResult {
    let prk = [0x42u8; 32];
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    hkdf_expand(&prk, b"info1", &mut okm1);
    hkdf_expand(&prk, b"info2", &mut okm2);
    if okm1 == okm2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hkdf_expand_64_bytes() -> TestResult {
    let prk = [0x42u8; 32];
    let info = b"application info";
    let mut okm = [0u8; 64];
    hkdf_expand(&prk, info, &mut okm);
    if !okm.iter().any(|&b| b != 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ripemd160_empty() -> TestResult {
    let hash = ripemd160(b"");
    if hash.len() != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ripemd160_abc() -> TestResult {
    let hash = ripemd160(b"abc");
    if hash.len() != 20 {
        return TestResult::Fail;
    }
    if hash == [0u8; 20] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ripemd160_deterministic() -> TestResult {
    let hash1 = ripemd160(b"test");
    let hash2 = ripemd160(b"test");
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_different_hash_algorithms_different_output() -> TestResult {
    let input = b"test input";
    let s256 = sha256(input);
    let s512 = sha512(input);
    let b3 = blake3_hash(input);
    let sha3 = sha3_256(input);
    let k256 = keccak256(input);

    if &s256[..] == &s512[..32] {
        return TestResult::Fail;
    }
    if &s256[..] == &b3[..] {
        return TestResult::Fail;
    }
    if &s256[..] == &sha3[..] {
        return TestResult::Fail;
    }
    if &s256[..] == &k256[..] {
        return TestResult::Fail;
    }
    if &b3[..] == &sha3[..] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_large_input_hashing() -> TestResult {
    let large_input: [u8; 4096] = [0x42; 4096];
    let hash = sha256(&large_input);
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_single_byte_inputs_all_different() -> TestResult {
    let hashes: [[u8; 32]; 256] = core::array::from_fn(|i| sha256(&[i as u8]));
    for i in 0..256 {
        for j in (i + 1)..256 {
            if hashes[i] == hashes[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
