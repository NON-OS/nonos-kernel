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

use super::framework::{TestCase, TestResult, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("Crypto");

    suite.add(TestCase::new("blake3_deterministic", test_blake3_deterministic, "crypto"));
    suite.add(TestCase::new("blake3_different_inputs", test_blake3_different_inputs, "crypto"));
    suite.add(TestCase::new("sha3_256_basic", test_sha3_256_basic, "crypto"));
    suite.add(TestCase::new("sha3_512_basic", test_sha3_512_basic, "crypto"));
    suite.add(TestCase::new("ed25519_sign_verify", test_ed25519_sign_verify, "crypto"));
    suite.add(TestCase::new("ed25519_wrong_key", test_ed25519_wrong_key, "crypto"));
    suite.add(TestCase::new(
        "chacha20poly1305_roundtrip",
        test_chacha20poly1305_roundtrip,
        "crypto",
    ));
    suite.add(TestCase::new("chacha20poly1305_tamper", test_chacha20poly1305_tamper, "crypto"));
    suite.add(TestCase::new("rng_nonrepeating", test_rng_nonrepeating, "crypto"));
    suite.add(TestCase::new("rng_fills_buffer", test_rng_fills_buffer, "crypto"));
    suite.add(TestCase::new("aes_gcm_roundtrip", test_aes_gcm_roundtrip, "crypto"));
    suite.add(TestCase::new("constant_time_compare", test_constant_time_compare, "crypto"));

    let (_, failed, _) = suite.run_all();
    failed == 0
}

pub(crate) fn test_blake3_deterministic() -> TestResult {
    let input = b"NONOS Kernel Test";
    let hash1 = crate::crypto::blake3::blake3_hash(input);
    let hash2 = crate::crypto::blake3::blake3_hash(input);

    if hash1 != hash2 {
        return TestResult::Fail;
    }
    if hash1.len() != 32 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_blake3_different_inputs() -> TestResult {
    let hash1 = crate::crypto::blake3::blake3_hash(b"input1");
    let hash2 = crate::crypto::blake3::blake3_hash(b"input2");

    if hash1 == hash2 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_sha3_256_basic() -> TestResult {
    let input = b"test message";
    let hash = crate::crypto::sha3::sha3_256(input);

    if hash.len() != 32 {
        return TestResult::Fail;
    }

    let hash2 = crate::crypto::sha3::sha3_256(input);
    if hash != hash2 {
        return TestResult::Fail;
    }

    let hash3 = crate::crypto::sha3::sha3_256(b"different");
    if hash == hash3 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_sha3_512_basic() -> TestResult {
    let input = b"test message";
    let hash = crate::crypto::sha3::sha3_512(input);

    if hash.len() != 64 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ed25519_sign_verify() -> TestResult {
    let keypair = crate::crypto::ed25519::KeyPair::generate();
    let message = b"Sign this message";

    let signature = crate::crypto::ed25519::sign(&keypair, message);
    let valid = crate::crypto::ed25519::verify(&keypair.public, message, &signature);

    if !valid {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_ed25519_wrong_key() -> TestResult {
    let keypair1 = crate::crypto::ed25519::KeyPair::generate();
    let keypair2 = crate::crypto::ed25519::KeyPair::generate();
    let message = b"Sign this message";

    let signature = crate::crypto::ed25519::sign(&keypair1, message);
    let valid = crate::crypto::ed25519::verify(&keypair2.public, message, &signature);

    if valid {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_chacha20poly1305_roundtrip() -> TestResult {
    let key: [u8; 32] = crate::crypto::generate_secure_key();
    let nonce: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let plaintext = b"Secret message";
    let aad = b"additional data";

    let ciphertext =
        match crate::crypto::chacha20poly1305::aead_encrypt(&key, &nonce, aad, plaintext) {
            Ok(ct) => ct,
            Err(_) => return TestResult::Fail,
        };

    let decrypted =
        match crate::crypto::chacha20poly1305::aead_decrypt(&key, &nonce, aad, &ciphertext) {
            Ok(pt) => pt,
            Err(_) => return TestResult::Fail,
        };

    if decrypted.as_slice() != plaintext {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_chacha20poly1305_tamper() -> TestResult {
    let key: [u8; 32] = crate::crypto::generate_secure_key();
    let nonce: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let plaintext = b"Secret message";
    let aad = b"additional data";

    let mut ciphertext =
        match crate::crypto::chacha20poly1305::aead_encrypt(&key, &nonce, aad, plaintext) {
            Ok(ct) => ct,
            Err(_) => return TestResult::Fail,
        };

    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0xFF;
    }

    match crate::crypto::chacha20poly1305::aead_decrypt(&key, &nonce, aad, &ciphertext) {
        Ok(_) => TestResult::Fail,
        Err(_) => TestResult::Pass,
    }
}

pub(crate) fn test_rng_nonrepeating() -> TestResult {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    crate::crypto::rng::fill_random_bytes(&mut buf1);
    crate::crypto::rng::fill_random_bytes(&mut buf2);

    if buf1 == buf2 {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_rng_fills_buffer() -> TestResult {
    let mut buf = [0u8; 64];
    crate::crypto::rng::fill_random_bytes(&mut buf);

    let mut all_zero = true;
    for b in buf.iter() {
        if *b != 0 {
            all_zero = false;
            break;
        }
    }

    if all_zero {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_aes_gcm_roundtrip() -> TestResult {
    use crate::crypto::aes_gcm;

    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let plaintext = b"AES-GCM test message";
    let aad = b"header";

    let ciphertext = match aes_gcm::encrypt(&key, &nonce, aad, plaintext) {
        Ok(ct) => ct,
        Err(_) => return TestResult::Fail,
    };

    let decrypted = match aes_gcm::decrypt(&key, &nonce, aad, &ciphertext) {
        Ok(pt) => pt,
        Err(_) => return TestResult::Fail,
    };

    if decrypted.as_slice() != plaintext {
        return TestResult::Fail;
    }

    TestResult::Pass
}

pub(crate) fn test_constant_time_compare() -> TestResult {
    use crate::crypto::constant_time::ct_eq;

    let a = [1u8, 2, 3, 4, 5];
    let b = [1u8, 2, 3, 4, 5];
    let c = [1u8, 2, 3, 4, 6];

    if !ct_eq(&a, &b) {
        return TestResult::Fail;
    }
    if ct_eq(&a, &c) {
        return TestResult::Fail;
    }

    TestResult::Pass
}
