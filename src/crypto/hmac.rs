//! HMAC and HKDF Implementation for NONOS Kernel
//!
//! Real HMAC-SHA256 and HKDF-SHA256 implementations
//! Following RFC 2104 (HMAC) and RFC 5869 (HKDF)

use crate::crypto::hash::sha256;
use alloc::{vec, vec::Vec};

const HMAC_BLOCK_SIZE: usize = 64; // SHA-256 block size
const HMAC_OUTPUT_SIZE: usize = 32; // SHA-256 output size

/// HMAC-SHA256 implementation
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut actual_key = [0u8; HMAC_BLOCK_SIZE];

    // Key preprocessing
    if key.len() > HMAC_BLOCK_SIZE {
        // If key is longer than block size, hash it
        let hashed_key = sha256(key);
        actual_key[..HMAC_OUTPUT_SIZE].copy_from_slice(&hashed_key);
    } else {
        // If key is shorter, pad with zeros
        actual_key[..key.len()].copy_from_slice(key);
    }

    // Create inner and outer padding
    let mut inner_pad = [0x36u8; HMAC_BLOCK_SIZE]; // ipad
    let mut outer_pad = [0x5Cu8; HMAC_BLOCK_SIZE]; // opad

    // XOR key with padding
    for i in 0..HMAC_BLOCK_SIZE {
        inner_pad[i] ^= actual_key[i];
        outer_pad[i] ^= actual_key[i];
    }

    // Inner hash: H(K XOR ipad || message)
    let mut inner_data = Vec::with_capacity(HMAC_BLOCK_SIZE + data.len());
    inner_data.extend_from_slice(&inner_pad);
    inner_data.extend_from_slice(data);
    let inner_hash = sha256(&inner_data);

    // Outer hash: H(K XOR opad || inner_hash)
    let mut outer_data = Vec::with_capacity(HMAC_BLOCK_SIZE + HMAC_OUTPUT_SIZE);
    outer_data.extend_from_slice(&outer_pad);
    outer_data.extend_from_slice(&inner_hash);
    sha256(&outer_data)
}

/// HKDF-Extract: Extract pseudorandom key from input keying material
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let actual_salt = if salt.is_empty() {
        vec![0u8; HMAC_OUTPUT_SIZE] // RFC 5869: if no salt, use zero-filled
                                    // string
    } else {
        salt.to_vec()
    };

    hmac_sha256(&actual_salt, ikm)
}

/// HKDF-Expand: Expand pseudorandom key to desired length
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Result<Vec<u8>, &'static str> {
    if length > 255 * HMAC_OUTPUT_SIZE {
        return Err("HKDF output length too large");
    }

    let n = (length + HMAC_OUTPUT_SIZE - 1) / HMAC_OUTPUT_SIZE; // Ceiling division
    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
        let mut input = Vec::new();
        if i > 1 {
            input.extend_from_slice(&t); // T(i-1)
        }
        input.extend_from_slice(info);
        input.push(i as u8);

        t = hmac_sha256(prk, &input).to_vec();
        output.extend_from_slice(&t);
    }

    output.truncate(length);
    Ok(output)
}

/// HKDF full function: Extract-then-Expand
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, &'static str> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// PBKDF2-HMAC-SHA256 for key derivation
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Result<Vec<u8>, &'static str> {
    if length > (u32::MAX as usize) * HMAC_OUTPUT_SIZE {
        return Err("PBKDF2 output length too large");
    }

    let blocks_needed = (length + HMAC_OUTPUT_SIZE - 1) / HMAC_OUTPUT_SIZE;
    let mut output = Vec::with_capacity(length);

    for block in 1..=blocks_needed {
        let mut u = Vec::with_capacity(salt.len() + 4);
        u.extend_from_slice(salt);
        u.extend_from_slice(&(block as u32).to_be_bytes());

        let mut f = hmac_sha256(password, &u);
        let mut result = f;

        // Iterate the HMAC function
        for _ in 1..iterations {
            f = hmac_sha256(password, &f);
            // XOR with previous result
            for i in 0..HMAC_OUTPUT_SIZE {
                result[i] ^= f[i];
            }
        }

        output.extend_from_slice(&result);
    }

    output.truncate(length);
    Ok(output)
}

/// Message Authentication Code verification (constant-time)
pub fn verify_hmac(expected: &[u8], computed: &[u8]) -> bool {
    if expected.len() != computed.len() {
        return false;
    }

    let mut result = 0u8;
    for i in 0..expected.len() {
        result |= expected[i] ^ computed[i];
    }

    result == 0
}

/// HMAC-based Key Derivation Function for specific protocols
pub struct HmacKdf {
    prk: [u8; 32],
    counter: u8,
}

impl HmacKdf {
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        Self { prk: hkdf_extract(salt, ikm), counter: 0 }
    }

    pub fn expand_next(&mut self, info: &[u8], length: usize) -> Result<Vec<u8>, &'static str> {
        self.counter += 1;
        if self.counter == 0 {
            return Err("HMAC-KDF counter overflow");
        }

        let mut full_info = Vec::with_capacity(info.len() + 1);
        full_info.extend_from_slice(info);
        full_info.push(self.counter);

        hkdf_expand(&self.prk, &full_info, length)
    }

    pub fn get_prk(&self) -> &[u8; 32] {
        &self.prk
    }
}

/// Test vectors for HMAC-SHA256 (RFC 4231)
pub fn hmac_test_vectors() -> bool {
    // Test Case 1
    let key1 = [0x0B; 20];
    let data1 = b"Hi There";
    let expected1 = [
        0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53, 0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1,
        0x2B, 0x88, 0x1D, 0xC2, 0x00, 0xC9, 0x83, 0x3D, 0xA7, 0x26, 0xE9, 0x37, 0x6C, 0x2E, 0x32,
        0xCF, 0xF7,
    ];

    let result1 = hmac_sha256(&key1, data1);
    if result1 != expected1 {
        return false;
    }

    // Test Case 2
    let key2 = b"Jefe";
    let data2 = b"what do ya want for nothing?";
    let expected2 = [
        0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E, 0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xC7, 0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83, 0x9D, 0xEC, 0x58, 0xB9, 0x64, 0xEC,
        0x38, 0x43,
    ];

    let result2 = hmac_sha256(key2, data2);
    result2 == expected2
}

/// HKDF test vectors (RFC 5869)
pub fn hkdf_test_vectors() -> bool {
    // Test Case 1 - Basic test
    let ikm = [0x0B; 22];
    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    let info = [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9];
    let length = 42;

    let expected_prk = [
        0x07, 0x77, 0x09, 0x36, 0x2C, 0x2E, 0x32, 0xDF, 0x0D, 0xDC, 0x3F, 0x0D, 0xC4, 0x7B, 0xBA,
        0x63, 0x90, 0xB6, 0xC7, 0x3B, 0xB5, 0x0F, 0x9C, 0x31, 0x22, 0xEC, 0x84, 0x4A, 0xD7, 0xC2,
        0xB3, 0xE5,
    ];

    let prk = hkdf_extract(&salt, &ikm);
    if prk != expected_prk {
        return false;
    }

    let expected_okm = vec![
        0x3C, 0xB2, 0x5F, 0x25, 0xFA, 0xAC, 0xD5, 0x7A, 0x90, 0x43, 0x4F, 0x64, 0xD0, 0x36, 0x2F,
        0x2A, 0x2D, 0x2D, 0x0A, 0x90, 0xCF, 0x1A, 0x5A, 0x4C, 0x5D, 0xB0, 0x2D, 0x56, 0xEC, 0xC4,
        0xC5, 0xBF, 0x34, 0x00, 0x72, 0x08, 0xD5, 0xB8, 0x87, 0x18, 0x58, 0x65,
    ];

    match hkdf_expand(&prk, &info, length) {
        Ok(okm) => okm == expected_okm,
        Err(_) => false,
    }
}
