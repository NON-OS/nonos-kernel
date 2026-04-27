// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Symmetric encryption tests - AES-GCM and ChaCha20-Poly1305

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::symmetric::aes_gcm::{
    aes128_gcm_decrypt, aes128_gcm_encrypt, aes256_gcm_decrypt, aes256_gcm_encrypt, Aes128Gcm,
    Aes256Gcm,
};
use crate::crypto::symmetric::chacha20poly1305::{
    aead_decrypt, aead_decrypt_in_place, aead_encrypt, aead_encrypt_in_place, chacha20_block,
    poly1305_mac, TAG_SIZE,
};
use crate::test::framework::TestResult;

pub(crate) fn test_aes128_gcm_nist_case_1() -> TestResult {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt: &[u8] = &[];
    let expected_tag: [u8; 16] = [
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45,
        0x5a,
    ];

    let ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if ct.len() != 16 {
        return TestResult::Fail;
    }
    if &ct[..] != &expected_tag[..] {
        return TestResult::Fail;
    }

    let dec = match aes128_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_nist_case_2() -> TestResult {
    let key = [0u8; 16];
    let nonce = [0u8; 12];
    let aad: &[u8] = &[];
    let pt = [0u8; 16];
    let expected_ct: [u8; 16] = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78,
    ];
    let expected_tag: [u8; 16] = [
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd,
        0xdf,
    ];

    let result = match aes128_gcm_encrypt(&key, &nonce, aad, &pt) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail,
    };
    if result.len() != 32 {
        return TestResult::Fail;
    }
    if &result[..16] != &expected_ct[..] {
        return TestResult::Fail;
    }
    if &result[16..] != &expected_tag[..] {
        return TestResult::Fail;
    }

    let dec = match aes128_gcm_decrypt(&key, &nonce, aad, &result) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_roundtrip() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"additional authenticated data";
    let pt = b"secret message to encrypt";

    let ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if ct.len() != pt.len() + 16 {
        return TestResult::Fail;
    }

    let dec = match aes128_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_tag_tampering() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    if aes128_gcm_decrypt(&key, &nonce, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_ciphertext_tampering() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    ct[0] ^= 0x01;

    if aes128_gcm_decrypt(&key, &nonce, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_aad_tampering() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if aes128_gcm_decrypt(&key, &nonce, b"Header", &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_short_ciphertext() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let short_ct = [0u8; 15];

    if aes128_gcm_decrypt(&key, &nonce, aad, &short_ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_empty_plaintext() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"";

    let ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if ct.len() != 16 {
        return TestResult::Fail;
    }

    let dec = match aes128_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_empty_aad() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let pt = b"secret message";

    let ct = match aes128_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let dec = match aes128_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_in_place() -> TestResult {
    let gcm = Aes128Gcm::new(&[0x42u8; 16]);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret message for in-place";

    let mut buffer = pt.to_vec();
    let tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);

    if gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).is_err() {
        return TestResult::Fail;
    }
    if &buffer[..] != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_in_place_tag_tamper() -> TestResult {
    let gcm = Aes128Gcm::new(&[0x42u8; 16]);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut buffer = pt.to_vec();
    let mut tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);
    tag[0] ^= 0x01;

    if gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes128_gcm_large_plaintext() -> TestResult {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt: Vec<u8> = (0..4096).map(|i| i as u8).collect();

    let ct = match aes128_gcm_encrypt(&key, &nonce, aad, &pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let dec = match aes128_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes256_gcm_roundtrip() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"additional authenticated data";
    let pt = b"secret message to encrypt with aes256";

    let ct = match aes256_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if ct.len() != pt.len() + 16 {
        return TestResult::Fail;
    }

    let dec = match aes256_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes256_gcm_tag_tampering() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = match aes256_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    if aes256_gcm_decrypt(&key, &nonce, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes256_gcm_ciphertext_tampering() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let mut ct = match aes256_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    ct[0] ^= 0x01;

    if aes256_gcm_decrypt(&key, &nonce, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes256_gcm_empty_plaintext() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"";

    let ct = match aes256_gcm_encrypt(&key, &nonce, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if ct.len() != 16 {
        return TestResult::Fail;
    }

    let dec = match aes256_gcm_decrypt(&key, &nonce, aad, &ct) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if dec != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes256_gcm_in_place() -> TestResult {
    let gcm = Aes256Gcm::new(&[0x42u8; 32]);
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let pt = b"secret message for in-place aes256";

    let mut buffer = pt.to_vec();
    let tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);

    if gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).is_err() {
        return TestResult::Fail;
    }
    if &buffer[..] != pt {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_rfc8439_block() -> TestResult {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];

    let mut output = [0u8; 64];
    chacha20_block(&key, &nonce, 1, &mut output);

    let expected = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];
    if output != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_rfc8439_aead() -> TestResult {
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce = [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
    let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

    let expected_ciphertext = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    let expected_tag = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];

    let result = match aead_encrypt(&key, &nonce, &aad, plaintext) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail,
    };

    if &result[..expected_ciphertext.len()] != &expected_ciphertext[..] {
        return TestResult::Fail;
    }
    if &result[expected_ciphertext.len()..] != &expected_tag[..] {
        return TestResult::Fail;
    }

    let decrypted = match aead_decrypt(&key, &nonce, &aad, &result) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if decrypted != plaintext {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_tag_tampering() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let mut ciphertext = match aead_encrypt(&key, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    if aead_decrypt(&key, &nonce, aad, &ciphertext).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_ciphertext_tampering() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let mut ciphertext = match aead_encrypt(&key, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    ciphertext[0] ^= 0x01;

    if aead_decrypt(&key, &nonce, aad, &ciphertext).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_aad_tampering() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ciphertext = match aead_encrypt(&key, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if aead_decrypt(&key, &nonce, b"Header", &ciphertext).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_empty_plaintext() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"";

    let ciphertext = match aead_encrypt(&key, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if ciphertext.len() != TAG_SIZE {
        return TestResult::Fail;
    }

    let decrypted = match aead_decrypt(&key, &nonce, aad, &ciphertext) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if decrypted != plaintext {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_empty_aad() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"";
    let plaintext = b"secret data";

    let ciphertext = match aead_encrypt(&key, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let decrypted = match aead_decrypt(&key, &nonce, aad, &ciphertext) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if decrypted != plaintext {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_in_place() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data for in-place test";

    let mut buffer = [0u8; 256];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    let ct_len = match aead_encrypt_in_place(&key, &nonce, aad, &mut buffer, plaintext.len()) {
        Ok(l) => l,
        Err(_) => return TestResult::Fail,
    };

    let pt_len = match aead_decrypt_in_place(&key, &nonce, aad, &mut buffer, ct_len) {
        Ok(l) => l,
        Err(_) => return TestResult::Fail,
    };

    if pt_len != plaintext.len() {
        return TestResult::Fail;
    }
    if &buffer[..pt_len] != plaintext {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_large_plaintext() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext: Vec<u8> = (0..4096).map(|i| i as u8).collect();

    let ciphertext = match aead_encrypt(&key, &nonce, aad, &plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let decrypted = match aead_decrypt(&key, &nonce, aad, &ciphertext) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail,
    };
    if decrypted != plaintext {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_poly1305_rfc8439_mac() -> TestResult {
    let key = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let msg = b"Cryptographic Forum Research Group";

    let tag = poly1305_mac(msg, &key);

    let expected = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];
    if tag != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_poly1305_deterministic() -> TestResult {
    let key = [0xff; 32];
    let tag1 = poly1305_mac(b"test", &key);
    let tag2 = poly1305_mac(b"test", &key);
    if tag1 != tag2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_short_ciphertext() -> TestResult {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let short_ct = [0u8; 15];

    if aead_decrypt(&key, &nonce, aad, &short_ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_different_keys() -> TestResult {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = match aead_encrypt(&key1, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let ct2 = match aead_encrypt(&key2, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if ct1 == ct2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_different_nonces() -> TestResult {
    let key = [0x42u8; 32];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = match aead_encrypt(&key, &nonce1, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let ct2 = match aead_encrypt(&key, &nonce2, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if ct1 == ct2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes_gcm_different_keys() -> TestResult {
    let key1 = [0x42u8; 16];
    let key2 = [0x43u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = match aes128_gcm_encrypt(&key1, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let ct2 = match aes128_gcm_encrypt(&key2, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if ct1 == ct2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes_gcm_different_nonces() -> TestResult {
    let key = [0x42u8; 16];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct1 = match aes128_gcm_encrypt(&key, &nonce1, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    let ct2 = match aes128_gcm_encrypt(&key, &nonce2, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if ct1 == ct2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes_gcm_cross_key_decrypt() -> TestResult {
    let key1 = [0x42u8; 16];
    let key2 = [0x43u8; 16];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct = match aes128_gcm_encrypt(&key1, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if aes128_gcm_decrypt(&key2, &nonce, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_cross_key_decrypt() -> TestResult {
    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"header";
    let plaintext = b"secret data";

    let ct = match aead_encrypt(&key1, &nonce, aad, plaintext) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };

    if aead_decrypt(&key2, &nonce, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_aes_gcm_wrong_nonce() -> TestResult {
    let key = [0x42u8; 16];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let ct = match aes128_gcm_encrypt(&key, &nonce1, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if aes128_gcm_decrypt(&key, &nonce2, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_chacha20_poly1305_wrong_nonce() -> TestResult {
    let key = [0x42u8; 32];
    let nonce1 = [0x24u8; 12];
    let nonce2 = [0x25u8; 12];
    let aad = b"header";
    let pt = b"secret";

    let ct = match aead_encrypt(&key, &nonce1, aad, pt) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail,
    };
    if aead_decrypt(&key, &nonce2, aad, &ct).is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
