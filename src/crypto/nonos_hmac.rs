//! HMAC and HKDF Implementation for NONOS Kernel
//!
//! Real HMAC-SHA256 and HKDF-SHA256 implementations
//! Following RFC 2104 (HMAC) and RFC 5869 (HKDF)

use alloc::{vec::Vec, vec};
use crate::crypto::hash::sha256;

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
        vec![0u8; HMAC_OUTPUT_SIZE] // RFC 5869: if no salt, use zero-filled string
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
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> Result<Vec<u8>, &'static str> {
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
        Self {
            prk: hkdf_extract(salt, ikm),
            counter: 0,
        }
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
    let key1 = [0x0b; 20];
    let data1 = b"Hi There";
    let expected1 = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    ];
    
    let result1 = hmac_sha256(&key1, data1);
    if result1 != expected1 {
        return false;
    }
    
    // Test Case 2
    let key2 = b"Jefe";
    let data2 = b"what do ya want for nothing?";
    let expected2 = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    ];
    
    let result2 = hmac_sha256(key2, data2);
    result2 == expected2
}

/// HKDF test vectors (RFC 5869)
pub fn hkdf_test_vectors() -> bool {
    // Test Case 1 - Basic test
    let ikm = [0x0b; 22];
    let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let length = 42;
    
    let expected_prk = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    ];
    
    let prk = hkdf_extract(&salt, &ikm);
    if prk != expected_prk {
        return false;
    }
    
    let expected_okm = vec![
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    ];
    
    match hkdf_expand(&prk, &info, length) {
        Ok(okm) => okm == expected_okm,
        Err(_) => false,
    }
}