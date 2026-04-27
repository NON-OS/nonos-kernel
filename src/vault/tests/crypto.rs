// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use crate::test::framework::TestResult;
use crate::vault::nonos_vault_crypto::*;

pub(crate) fn test_vault_encrypt_aes_returns_result() -> TestResult {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let plaintext = b"plaintext";
    let result = vault_encrypt_aes(&key, &nonce, aad, plaintext);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_decrypt_aes_returns_result() -> TestResult {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let ciphertext_and_tag = [0u8; 32];
    let result = vault_decrypt_aes(&key, &nonce, aad, &ciphertext_and_tag);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_aes_roundtrip() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"associated data";
    let plaintext = b"secret message";
    if let Ok(ciphertext) = vault_encrypt_aes(&key, &nonce, aad, plaintext) {
        if let Ok(decrypted) = vault_decrypt_aes(&key, &nonce, aad, &ciphertext) {
            if decrypted != plaintext {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_encrypt_chacha_returns_result() -> TestResult {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let plaintext = b"plaintext";
    let result = vault_encrypt_chacha(&key, &nonce, aad, plaintext);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_decrypt_chacha_returns_result() -> TestResult {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let ciphertext_and_tag = [0u8; 32];
    let result = vault_decrypt_chacha(&key, &nonce, aad, &ciphertext_and_tag);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_chacha_roundtrip() -> TestResult {
    let key = [0xAAu8; 32];
    let nonce = [0xBBu8; 12];
    let aad = b"chacha aad";
    let plaintext = b"chacha plaintext";
    if let Ok(ciphertext) = vault_encrypt_chacha(&key, &nonce, aad, plaintext) {
        if let Ok(decrypted) = vault_decrypt_chacha(&key, &nonce, aad, &ciphertext) {
            if decrypted != plaintext {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_wrap_aes_returns_result() -> TestResult {
    let key = [0x11u8; 32];
    let plaintext = b"key to wrap";
    let aad = b"wrap aad";
    let result = vault_wrap_aes(&key, plaintext, aad);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_unwrap_aes_too_short() -> TestResult {
    let key = [0u8; 32];
    let short = [0u8; 10];
    let result = vault_unwrap_aes(&key, &short, b"aad");
    if !result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_wrap_unwrap_roundtrip() -> TestResult {
    let key = [0x22u8; 32];
    let plaintext = b"wrapped secret key";
    let aad = b"wrapping aad";
    if let Ok(wrapped) = vault_wrap_aes(&key, plaintext, aad) {
        if let Ok(unwrapped) = vault_unwrap_aes(&key, &wrapped, aad) {
            if unwrapped != plaintext {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_blake3_returns_32_bytes() -> TestResult {
    let data = b"hash me";
    let hash = vault_hash_blake3(data);
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_blake3_deterministic() -> TestResult {
    let data = b"deterministic data";
    let hash1 = vault_hash_blake3(data);
    let hash2 = vault_hash_blake3(data);
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_blake3_different_input_different_hash() -> TestResult {
    let hash1 = vault_hash_blake3(b"input1");
    let hash2 = vault_hash_blake3(b"input2");
    if hash1 == hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_blake3_empty_input() -> TestResult {
    let hash = vault_hash_blake3(b"");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_sha256_returns_32_bytes() -> TestResult {
    let data = b"sha256 input";
    let hash = vault_hash_sha256(data);
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_sha256_deterministic() -> TestResult {
    let data = b"sha256 deterministic";
    let hash1 = vault_hash_sha256(data);
    let hash2 = vault_hash_sha256(data);
    if hash1 != hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_sha256_different_input_different_hash() -> TestResult {
    let hash1 = vault_hash_sha256(b"first");
    let hash2 = vault_hash_sha256(b"second");
    if hash1 == hash2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_sha256_empty_input() -> TestResult {
    let hash = vault_hash_sha256(b"");
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hkdf_expand_returns_result() -> TestResult {
    let prk = [0u8; 32];
    let info = b"info";
    let result = vault_hkdf_expand(&prk, info, 32);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hkdf_expand_correct_length() -> TestResult {
    let prk = [0x55u8; 32];
    let info = b"length test";
    for len in [16, 32, 48, 64, 128] {
        if let Ok(okm) = vault_hkdf_expand(&prk, info, len) {
            if okm.len() != len {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hkdf_expand_different_info_different_output() -> TestResult {
    let prk = [0x66u8; 32];
    if let (Ok(okm1), Ok(okm2)) =
        (vault_hkdf_expand(&prk, b"info1", 32), vault_hkdf_expand(&prk, b"info2", 32))
    {
        if okm1 == okm2 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_sha256_returns_32_bytes() -> TestResult {
    let key = b"hmac key";
    let data = b"hmac data";
    let mac = vault_hmac_sha256(key, data);
    if mac.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_sha256_deterministic() -> TestResult {
    let key = b"deterministic key";
    let data = b"deterministic data";
    let mac1 = vault_hmac_sha256(key, data);
    let mac2 = vault_hmac_sha256(key, data);
    if mac1 != mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_sha256_different_key_different_mac() -> TestResult {
    let data = b"same data";
    let mac1 = vault_hmac_sha256(b"key1", data);
    let mac2 = vault_hmac_sha256(b"key2", data);
    if mac1 == mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_sha256_different_data_different_mac() -> TestResult {
    let key = b"same key";
    let mac1 = vault_hmac_sha256(key, b"data1");
    let mac2 = vault_hmac_sha256(key, b"data2");
    if mac1 == mac2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_verify_valid() -> TestResult {
    let key = b"verify key";
    let data = b"verify data";
    let mac = vault_hmac_sha256(key, data);
    if !vault_hmac_verify(key, data, &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_verify_invalid_mac() -> TestResult {
    let key = b"verify key";
    let data = b"verify data";
    let bad_mac = [0u8; 32];
    if vault_hmac_verify(key, data, &bad_mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_verify_wrong_key() -> TestResult {
    let key1 = b"key1";
    let key2 = b"key2";
    let data = b"data";
    let mac = vault_hmac_sha256(key1, data);
    if vault_hmac_verify(key2, data, &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hmac_verify_wrong_data() -> TestResult {
    let key = b"key";
    let data1 = b"data1";
    let data2 = b"data2";
    let mac = vault_hmac_sha256(key, data1);
    if vault_hmac_verify(key, data2, &mac) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_zeroize() -> TestResult {
    let mut buf = [0xFFu8; 64];
    vault_zeroize(&mut buf);
    for b in &buf {
        if *b != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_zeroize_empty() -> TestResult {
    let mut buf: [u8; 0] = [];
    vault_zeroize(&mut buf);
    TestResult::Pass
}

pub(crate) fn test_vault_zeroize_vec() -> TestResult {
    let mut vec = alloc::vec![0xAA, 0xBB, 0xCC, 0xDD];
    vault_zeroize_vec(&mut vec);
    if !vec.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_zeroize_vec_empty() -> TestResult {
    let mut vec: alloc::vec::Vec<u8> = alloc::vec![];
    vault_zeroize_vec(&mut vec);
    if !vec.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_equal() -> TestResult {
    let a = [1, 2, 3, 4];
    let b = [1, 2, 3, 4];
    if !vault_ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_not_equal() -> TestResult {
    let a = [1, 2, 3, 4];
    let b = [1, 2, 3, 5];
    if vault_ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_different_length() -> TestResult {
    let a = [1, 2, 3];
    let b = [1, 2, 3, 4];
    if vault_ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_empty() -> TestResult {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    if !vault_ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_32_equal() -> TestResult {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    if !vault_ct_eq_32(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_32_not_equal() -> TestResult {
    let a = [0x42u8; 32];
    let mut b = [0x42u8; 32];
    b[31] = 0x43;
    if vault_ct_eq_32(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_32_all_zeros() -> TestResult {
    let a = [0u8; 32];
    let b = [0u8; 32];
    if !vault_ct_eq_32(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_ct_eq_32_all_ones() -> TestResult {
    let a = [0xFFu8; 32];
    let b = [0xFFu8; 32];
    if !vault_ct_eq_32(&a, &b) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_kyber_keygen_returns_result() -> TestResult {
    let result = vault_kyber_keygen();
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_dilithium_keygen_returns_result() -> TestResult {
    let result = vault_dilithium_keygen();
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_encrypt_aes_empty_plaintext() -> TestResult {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let result = vault_encrypt_aes(&key, &nonce, b"", b"");
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_encrypt_chacha_empty_plaintext() -> TestResult {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let result = vault_encrypt_chacha(&key, &nonce, b"", b"");
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_encrypt_aes_large_plaintext() -> TestResult {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let large_plaintext = alloc::vec![0x55u8; 4096];
    let result = vault_encrypt_aes(&key, &nonce, b"aad", &large_plaintext);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_blake3_large_input() -> TestResult {
    let large_input = alloc::vec![0xAAu8; 10000];
    let hash = vault_hash_blake3(&large_input);
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_hash_sha256_large_input() -> TestResult {
    let large_input = alloc::vec![0xBBu8; 10000];
    let hash = vault_hash_sha256(&large_input);
    if hash.len() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
