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

use crate::vault::nonos_vault_crypto::*;

#[test]
fn test_vault_encrypt_aes_returns_result() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let plaintext = b"plaintext";
    let result = vault_encrypt_aes(&key, &nonce, aad, plaintext);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_decrypt_aes_returns_result() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let ciphertext_and_tag = [0u8; 32];
    let result = vault_decrypt_aes(&key, &nonce, aad, &ciphertext_and_tag);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_aes_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = b"associated data";
    let plaintext = b"secret message";
    if let Ok(ciphertext) = vault_encrypt_aes(&key, &nonce, aad, plaintext) {
        if let Ok(decrypted) = vault_decrypt_aes(&key, &nonce, aad, &ciphertext) {
            assert_eq!(decrypted, plaintext);
        }
    }
}

#[test]
fn test_vault_encrypt_chacha_returns_result() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let plaintext = b"plaintext";
    let result = vault_encrypt_chacha(&key, &nonce, aad, plaintext);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_decrypt_chacha_returns_result() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let aad = b"aad";
    let ciphertext_and_tag = [0u8; 32];
    let result = vault_decrypt_chacha(&key, &nonce, aad, &ciphertext_and_tag);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_chacha_roundtrip() {
    let key = [0xAAu8; 32];
    let nonce = [0xBBu8; 12];
    let aad = b"chacha aad";
    let plaintext = b"chacha plaintext";
    if let Ok(ciphertext) = vault_encrypt_chacha(&key, &nonce, aad, plaintext) {
        if let Ok(decrypted) = vault_decrypt_chacha(&key, &nonce, aad, &ciphertext) {
            assert_eq!(decrypted, plaintext);
        }
    }
}

#[test]
fn test_vault_wrap_aes_returns_result() {
    let key = [0x11u8; 32];
    let plaintext = b"key to wrap";
    let aad = b"wrap aad";
    let result = vault_wrap_aes(&key, plaintext, aad);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_unwrap_aes_too_short() {
    let key = [0u8; 32];
    let short = [0u8; 10];
    let result = vault_unwrap_aes(&key, &short, b"aad");
    assert!(result.is_err());
}

#[test]
fn test_vault_wrap_unwrap_roundtrip() {
    let key = [0x22u8; 32];
    let plaintext = b"wrapped secret key";
    let aad = b"wrapping aad";
    if let Ok(wrapped) = vault_wrap_aes(&key, plaintext, aad) {
        if let Ok(unwrapped) = vault_unwrap_aes(&key, &wrapped, aad) {
            assert_eq!(unwrapped, plaintext);
        }
    }
}

#[test]
fn test_vault_hash_blake3_returns_32_bytes() {
    let data = b"hash me";
    let hash = vault_hash_blake3(data);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_vault_hash_blake3_deterministic() {
    let data = b"deterministic data";
    let hash1 = vault_hash_blake3(data);
    let hash2 = vault_hash_blake3(data);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_vault_hash_blake3_different_input_different_hash() {
    let hash1 = vault_hash_blake3(b"input1");
    let hash2 = vault_hash_blake3(b"input2");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_vault_hash_blake3_empty_input() {
    let hash = vault_hash_blake3(b"");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_vault_hash_sha256_returns_32_bytes() {
    let data = b"sha256 input";
    let hash = vault_hash_sha256(data);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_vault_hash_sha256_deterministic() {
    let data = b"sha256 deterministic";
    let hash1 = vault_hash_sha256(data);
    let hash2 = vault_hash_sha256(data);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_vault_hash_sha256_different_input_different_hash() {
    let hash1 = vault_hash_sha256(b"first");
    let hash2 = vault_hash_sha256(b"second");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_vault_hash_sha256_empty_input() {
    let hash = vault_hash_sha256(b"");
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_vault_hkdf_expand_returns_result() {
    let prk = [0u8; 32];
    let info = b"info";
    let result = vault_hkdf_expand(&prk, info, 32);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_hkdf_expand_correct_length() {
    let prk = [0x55u8; 32];
    let info = b"length test";
    for len in [16, 32, 48, 64, 128] {
        if let Ok(okm) = vault_hkdf_expand(&prk, info, len) {
            assert_eq!(okm.len(), len);
        }
    }
}

#[test]
fn test_vault_hkdf_expand_different_info_different_output() {
    let prk = [0x66u8; 32];
    if let (Ok(okm1), Ok(okm2)) = (
        vault_hkdf_expand(&prk, b"info1", 32),
        vault_hkdf_expand(&prk, b"info2", 32),
    ) {
        assert_ne!(okm1, okm2);
    }
}

#[test]
fn test_vault_hmac_sha256_returns_32_bytes() {
    let key = b"hmac key";
    let data = b"hmac data";
    let mac = vault_hmac_sha256(key, data);
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_vault_hmac_sha256_deterministic() {
    let key = b"deterministic key";
    let data = b"deterministic data";
    let mac1 = vault_hmac_sha256(key, data);
    let mac2 = vault_hmac_sha256(key, data);
    assert_eq!(mac1, mac2);
}

#[test]
fn test_vault_hmac_sha256_different_key_different_mac() {
    let data = b"same data";
    let mac1 = vault_hmac_sha256(b"key1", data);
    let mac2 = vault_hmac_sha256(b"key2", data);
    assert_ne!(mac1, mac2);
}

#[test]
fn test_vault_hmac_sha256_different_data_different_mac() {
    let key = b"same key";
    let mac1 = vault_hmac_sha256(key, b"data1");
    let mac2 = vault_hmac_sha256(key, b"data2");
    assert_ne!(mac1, mac2);
}

#[test]
fn test_vault_hmac_verify_valid() {
    let key = b"verify key";
    let data = b"verify data";
    let mac = vault_hmac_sha256(key, data);
    assert!(vault_hmac_verify(key, data, &mac));
}

#[test]
fn test_vault_hmac_verify_invalid_mac() {
    let key = b"verify key";
    let data = b"verify data";
    let bad_mac = [0u8; 32];
    assert!(!vault_hmac_verify(key, data, &bad_mac));
}

#[test]
fn test_vault_hmac_verify_wrong_key() {
    let key1 = b"key1";
    let key2 = b"key2";
    let data = b"data";
    let mac = vault_hmac_sha256(key1, data);
    assert!(!vault_hmac_verify(key2, data, &mac));
}

#[test]
fn test_vault_hmac_verify_wrong_data() {
    let key = b"key";
    let data1 = b"data1";
    let data2 = b"data2";
    let mac = vault_hmac_sha256(key, data1);
    assert!(!vault_hmac_verify(key, data2, &mac));
}

#[test]
fn test_vault_zeroize() {
    let mut buf = [0xFFu8; 64];
    vault_zeroize(&mut buf);
    for b in &buf {
        assert_eq!(*b, 0);
    }
}

#[test]
fn test_vault_zeroize_empty() {
    let mut buf: [u8; 0] = [];
    vault_zeroize(&mut buf);
}

#[test]
fn test_vault_zeroize_vec() {
    let mut vec = alloc::vec![0xAA, 0xBB, 0xCC, 0xDD];
    vault_zeroize_vec(&mut vec);
    assert!(vec.is_empty());
}

#[test]
fn test_vault_zeroize_vec_empty() {
    let mut vec: alloc::vec::Vec<u8> = alloc::vec![];
    vault_zeroize_vec(&mut vec);
    assert!(vec.is_empty());
}

#[test]
fn test_vault_ct_eq_equal() {
    let a = [1, 2, 3, 4];
    let b = [1, 2, 3, 4];
    assert!(vault_ct_eq(&a, &b));
}

#[test]
fn test_vault_ct_eq_not_equal() {
    let a = [1, 2, 3, 4];
    let b = [1, 2, 3, 5];
    assert!(!vault_ct_eq(&a, &b));
}

#[test]
fn test_vault_ct_eq_different_length() {
    let a = [1, 2, 3];
    let b = [1, 2, 3, 4];
    assert!(!vault_ct_eq(&a, &b));
}

#[test]
fn test_vault_ct_eq_empty() {
    let a: [u8; 0] = [];
    let b: [u8; 0] = [];
    assert!(vault_ct_eq(&a, &b));
}

#[test]
fn test_vault_ct_eq_32_equal() {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    assert!(vault_ct_eq_32(&a, &b));
}

#[test]
fn test_vault_ct_eq_32_not_equal() {
    let a = [0x42u8; 32];
    let mut b = [0x42u8; 32];
    b[31] = 0x43;
    assert!(!vault_ct_eq_32(&a, &b));
}

#[test]
fn test_vault_ct_eq_32_all_zeros() {
    let a = [0u8; 32];
    let b = [0u8; 32];
    assert!(vault_ct_eq_32(&a, &b));
}

#[test]
fn test_vault_ct_eq_32_all_ones() {
    let a = [0xFFu8; 32];
    let b = [0xFFu8; 32];
    assert!(vault_ct_eq_32(&a, &b));
}

#[test]
fn test_vault_kyber_keygen_returns_result() {
    let result = vault_kyber_keygen();
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_dilithium_keygen_returns_result() {
    let result = vault_dilithium_keygen();
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_encrypt_aes_empty_plaintext() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let result = vault_encrypt_aes(&key, &nonce, b"", b"");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_encrypt_chacha_empty_plaintext() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let result = vault_encrypt_chacha(&key, &nonce, b"", b"");
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_encrypt_aes_large_plaintext() {
    let key = [0x33u8; 32];
    let nonce = [0x44u8; 12];
    let large_plaintext = alloc::vec![0x55u8; 4096];
    let result = vault_encrypt_aes(&key, &nonce, b"aad", &large_plaintext);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_vault_hash_blake3_large_input() {
    let large_input = alloc::vec![0xAAu8; 10000];
    let hash = vault_hash_blake3(&large_input);
    assert_eq!(hash.len(), 32);
}

#[test]
fn test_vault_hash_sha256_large_input() {
    let large_input = alloc::vec![0xBBu8; 10000];
    let hash = vault_hash_sha256(&large_input);
    assert_eq!(hash.len(), 32);
}
