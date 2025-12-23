// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
// 
//! AES-256-GCM Authenticated Encryption with Associated Data
//!
//! Following NIST SP 800-38D (Recommendation for Block Cipher
//! Modes of Operation: Galois/Counter Mode (GCM) and GMAC).
//!
//! # Security Properties
//!
//! - **Confidentiality**: AES-256 in CTR mode provides semantic security
//! - **Authenticity**: GHASH provides 128-bit authentication tag
//! - **Constant-time**: All operations are designed to be constant-time
//!   to prevent timing side-channel attacks
//!
//! # Nonce Requirements
//!
//! **CRITICAL**: Never reuse a nonce with the same key. Nonce reuse completely
//! breaks the security of GCM, allowing:
//! - Recovery of the authentication key H
//! - Forgery of arbitrary messages
//! - Potential plaintext recovery
//!
//! For 96-bit nonces (recommended), either:
//! - Counter-based nonces with unique key per context
//! - Random nonces with collision probability consideration (birthday bound)

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::aes::Aes256;
use crate::crypto::constant_time::{ct_eq_16, secure_zero, compiler_fence};

// ============================================================================
// CONSTANTS
// ============================================================================

/// GCM authentication tag size in bytes
pub const TAG_SIZE: usize = 16;

/// GCM nonce size in bytes (96-bit recommended)
pub const NONCE_SIZE: usize = 12;

/// AES block size
const BLOCK_SIZE: usize = 16;

/// GF(2^128) reduction polynomial: x^128 + x^7 + x^2 + x + 1
/// Represented as the upper 64 bits of the polynomial (0xE1 << 56)
const GF128_R: u64 = 0xE100_0000_0000_0000;

// ============================================================================
// GHASH SUBKEY (H)
// ============================================================================

/// GHASH authentication subkey with precomputed tables for optimization
#[derive(Clone)]
struct GhashKey {
    /// H = E_K(0^128) represented as (hi, lo) in big-endian bit ordering
    h: (u64, u64),
    /// Precomputed H*x^i for i=0..15 (4-bit table)
    /// This allows processing 4 bits at a time instead of 1
    table: [(u64, u64); 16],
}

impl GhashKey {
    /// Create a new GHASH key from AES-encrypted zero block
    fn new(aes: &Aes256) -> Self {
        let zero = [0u8; BLOCK_SIZE];
        let h_block = aes.encrypt_block(&zero);

        let h = block_to_u128(&h_block);

        // Precompute table: table[i] = i * H for i in 0..16
        // Uses GCM's reflected bit ordering with right-shift doubling
        let mut table = [(0u64, 0u64); 16];
        table[0] = (0, 0);  // 0 * H = 0
        table[8] = h;       // 8 = 0b1000, represents x^0 in reflected ordering

        // Build table using the GCM "double" operation (right shift with reduction)
        // In GCM's reflected bit ordering:
        // - Bit position 0 (LSB) is x^127, bit position 127 (MSB) is x^0
        // - "Doubling" shifts right and conditionally XORs the reduction polynomial
        for i in [4, 2, 1] {
            table[i] = gf128_double_gcm(table[i * 2]);
        }

        // Fill remaining entries using XOR
        for i in 0..16 {
            if table[i] == (0, 0) && i != 0 {
                // Build from lower entries
                let hi_bit = i & 8;
                let rest = i & 7;
                if hi_bit != 0 && rest != 0 {
                    table[i] = gf128_xor(table[hi_bit], table[rest]);
                }
            }
        }

        Self { h, table }
    }

    /// Multiply a 128-bit value by H using bit-by-bit method (constant-time)
    #[inline]
    fn mul(&self, x: (u64, u64)) -> (u64, u64) {
        // Use the proven bitwise implementation for correctness
        gf128_mul_bitwise(x, self.h)
    }
}

impl Drop for GhashKey {
    fn drop(&mut self) {
        // Securely erase the hash subkey
        self.h = (0, 0);
        for entry in &mut self.table {
            *entry = (0, 0);
        }
        compiler_fence();
    }
}

// ============================================================================
// GF(2^128) FIELD OPERATIONS
// ============================================================================

/// Convert 16-byte block to (u64, u64) in big-endian bit ordering
#[inline]
fn block_to_u128(block: &[u8; 16]) -> (u64, u64) {
    let hi = u64::from_be_bytes([
        block[0], block[1], block[2], block[3],
        block[4], block[5], block[6], block[7],
    ]);
    let lo = u64::from_be_bytes([
        block[8], block[9], block[10], block[11],
        block[12], block[13], block[14], block[15],
    ]);
    (hi, lo)
}

/// Convert (u64, u64) to 16-byte block in big-endian
#[inline]
fn u128_to_block(val: (u64, u64)) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[0..8].copy_from_slice(&val.0.to_be_bytes());
    block[8..16].copy_from_slice(&val.1.to_be_bytes());
    block
}

/// XOR two 128-bit values
#[inline(always)]
fn gf128_xor(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    (a.0 ^ b.0, a.1 ^ b.1)
}

/// Double a value in GF(2^128) with left shift: result = x * 2
/// If MSB was set, reduce by the polynomial
#[inline]
#[allow(dead_code)]
fn gf128_double(x: (u64, u64)) -> (u64, u64) {
    // Check if MSB is set (will need reduction)
    let msb = (x.0 >> 63) & 1;

    // Left shift by 1 (multiply by x)
    let hi = (x.0 << 1) | (x.1 >> 63);
    let lo = x.1 << 1;

    // Conditional reduction: if MSB was set, XOR with R
    // Use constant-time selection
    let reduce_mask = 0u64.wrapping_sub(msb);
    (hi, lo ^ (reduce_mask & GF128_R))
}

/// GCM-style doubling: right shift with reduction on LSB
/// This is the correct direction for GCM's reflected bit ordering
#[inline]
fn gf128_double_gcm(x: (u64, u64)) -> (u64, u64) {
    // Check if LSB is set (will need reduction)
    let lsb = x.1 & 1;

    // Right shift by 1
    let lo = (x.1 >> 1) | (x.0 << 63);
    let hi = x.0 >> 1;

    // Conditional reduction: if LSB was set, XOR with R into high bits
    let reduce_mask = 0u64.wrapping_sub(lsb);
    (hi ^ (reduce_mask & GF128_R), lo)
}

/// Multiply two values in GF(2^128) using bit-by-bit method
/// This is constant-time but slower than table-based approaches
#[inline(never)]
fn gf128_mul_bitwise(x: (u64, u64), y: (u64, u64)) -> (u64, u64) {
    let mut z = (0u64, 0u64);
    let mut v = y;

    // Process high 64 bits
    for i in 0..64 {
        let bit = (x.0 >> (63 - i)) & 1;
        let mask = 0u64.wrapping_sub(bit);
        z.0 ^= v.0 & mask;
        z.1 ^= v.1 & mask;

        // v = v * x (right shift with reduction)
        let lsb = v.1 & 1;
        v.1 = (v.1 >> 1) | (v.0 << 63);
        v.0 >>= 1;
        let reduce_mask = 0u64.wrapping_sub(lsb);
        v.0 ^= reduce_mask & GF128_R;
    }

    // Process low 64 bits
    for i in 0..64 {
        let bit = (x.1 >> (63 - i)) & 1;
        let mask = 0u64.wrapping_sub(bit);
        z.0 ^= v.0 & mask;
        z.1 ^= v.1 & mask;

        // v = v * x (right shift with reduction)
        let lsb = v.1 & 1;
        v.1 = (v.1 >> 1) | (v.0 << 63);
        v.0 >>= 1;
        let reduce_mask = 0u64.wrapping_sub(lsb);
        v.0 ^= reduce_mask & GF128_R;
    }

    z
}

/// Multiply using precomputed table (4 bits at a time)
/// Processes 32 nibbles (4-bit chunks) for full 128-bit multiplication
#[inline]
fn gf128_mul_precomputed(x: (u64, u64), table: &[(u64, u64); 16]) -> (u64, u64) {
    let mut z = (0u64, 0u64);

    // Process x from MSB to LSB, 4 bits at a time
    // Process high 64 bits (16 nibbles)
    for i in 0..16 {
        // Shift z right by 4 bits with reduction
        z = gf128_shift_right_4(z);

        // Get nibble from x (MSB first)
        let nibble = ((x.0 >> (60 - i * 4)) & 0xF) as usize;

        // XOR with precomputed table entry
        z = gf128_xor(z, table[nibble]);
    }

    // Process low 64 bits (16 nibbles)
    for i in 0..16 {
        z = gf128_shift_right_4(z);
        let nibble = ((x.1 >> (60 - i * 4)) & 0xF) as usize;
        z = gf128_xor(z, table[nibble]);
    }

    z
}

/// Shift right by 4 bits in GF(2^128) with reduction
#[inline]
fn gf128_shift_right_4(x: (u64, u64)) -> (u64, u64) {
    // Get the 4 LSBs that will be shifted out
    let lsb4 = x.1 & 0xF;

    // Shift right by 4
    let lo = (x.1 >> 4) | (x.0 << 60);
    let hi = x.0 >> 4;

    // Reduction table for 4-bit values
    // reduce[i] = i * R where R is the reduction polynomial
    const REDUCE: [u64; 16] = [
        0x0000_0000_0000_0000,
        0xE100_0000_0000_0000,
        0xC200_0000_0000_0000,
        0x2300_0000_0000_0000,
        0x8400_0000_0000_0000,
        0x6500_0000_0000_0000,
        0x4600_0000_0000_0000,
        0xA700_0000_0000_0000,
        0x0801_0000_0000_0000,
        0xE901_0000_0000_0000,
        0xCA01_0000_0000_0000,
        0x2B01_0000_0000_0000,
        0x8C01_0000_0000_0000,
        0x6D01_0000_0000_0000,
        0x4E01_0000_0000_0000,
        0xAF01_0000_0000_0000,
    ];

    (hi ^ REDUCE[lsb4 as usize], lo)
}

// ============================================================================
// GHASH COMPUTATION
// ============================================================================

/// GHASH state for incremental computation
struct GhashState {
    key: GhashKey,
    y: (u64, u64),      // Current accumulator
    aad_len: u64,       // Total AAD length in bytes
    ct_len: u64,        // Total ciphertext length in bytes
    buffer: [u8; 16],   // Partial block buffer
    buffer_len: usize,  // Bytes in buffer
    aad_done: bool,     // Whether AAD processing is complete
}

impl GhashState {
    fn new(key: GhashKey) -> Self {
        Self {
            key,
            y: (0, 0),
            aad_len: 0,
            ct_len: 0,
            buffer: [0u8; 16],
            buffer_len: 0,
            aad_done: false,
        }
    }

    /// Update GHASH with AAD (must be called before ciphertext)
    fn update_aad(&mut self, data: &[u8]) {
        debug_assert!(!self.aad_done, "AAD already finalized");
        self.aad_len += data.len() as u64;
        self.update_internal(data);
    }

    /// Finalize AAD processing and switch to ciphertext mode
    fn finalize_aad(&mut self) {
        if self.aad_done {
            return;
        }

        // Pad remaining AAD buffer
        if self.buffer_len > 0 {
            // Zero-pad the remaining buffer
            for i in self.buffer_len..16 {
                self.buffer[i] = 0;
            }
            let block = block_to_u128(&self.buffer);
            self.y = self.key.mul(gf128_xor(self.y, block));
            self.buffer_len = 0;
        }

        self.aad_done = true;
    }

    /// Update GHASH with ciphertext
    fn update_ct(&mut self, data: &[u8]) {
        if !self.aad_done {
            self.finalize_aad();
        }
        self.ct_len += data.len() as u64;
        self.update_internal(data);
    }

    /// Internal update function for both AAD and CT
    fn update_internal(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Process any buffered data first
        if self.buffer_len > 0 {
            let need = 16 - self.buffer_len;
            let take = need.min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            offset = take;

            if self.buffer_len == 16 {
                let block = block_to_u128(&self.buffer);
                self.y = self.key.mul(gf128_xor(self.y, block));
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + 16 <= data.len() {
            let block: [u8; 16] = data[offset..offset + 16].try_into().unwrap();
            let x = block_to_u128(&block);
            self.y = self.key.mul(gf128_xor(self.y, x));
            offset += 16;
        }

        // Buffer remaining partial block
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }

    /// Finalize GHASH and return the authentication value S
    fn finalize(mut self) -> (u64, u64) {
        if !self.aad_done {
            self.finalize_aad();
        }

        // Pad any remaining ciphertext
        if self.buffer_len > 0 {
            for i in self.buffer_len..16 {
                self.buffer[i] = 0;
            }
            let block = block_to_u128(&self.buffer);
            self.y = self.key.mul(gf128_xor(self.y, block));
        }

        // Process final length block: len(A) || len(C) in bits
        let len_block = (
            (self.aad_len * 8),   // AAD length in bits (high 64 bits)
            (self.ct_len * 8),    // CT length in bits (low 64 bits)
        );

        self.key.mul(gf128_xor(self.y, len_block))
    }
}

impl Drop for GhashState {
    fn drop(&mut self) {
        self.y = (0, 0);
        secure_zero(&mut self.buffer);
        self.buffer_len = 0;
        compiler_fence();
    }
}

// ============================================================================
// CTR MODE ENCRYPTION
// ============================================================================

/// Increment the last 32 bits of the counter (GCM inc32 function)
#[inline]
fn inc32(counter: &mut [u8; 16]) {
    let ctr = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    let incremented = ctr.wrapping_add(1);
    counter[12..16].copy_from_slice(&incremented.to_be_bytes());
}

/// Derive J0 from 96-bit nonce: J0 = nonce || 0x00000001
#[inline]
fn derive_j0(nonce: &[u8; 12]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    j0[0..12].copy_from_slice(nonce);
    j0[15] = 1; // Counter starts at 1
    j0
}

/// AES-CTR encryption/decryption for GCM
/// Encrypts data in-place starting from counter = J0 + 1
fn aes_ctr_gcm(aes: &Aes256, j0: &[u8; 16], data: &mut [u8]) {
    if data.is_empty() {
        return;
    }

    let mut counter = *j0;
    inc32(&mut counter); // Start from J0 + 1

    let mut offset = 0;
    while offset < data.len() {
        let keystream = aes.encrypt_block(&counter);
        let block_len = (data.len() - offset).min(16);

        for i in 0..block_len {
            data[offset + i] ^= keystream[i];
        }

        offset += block_len;
        inc32(&mut counter);
    }
}

// ============================================================================
// AES-256-GCM CONTEXT
// ============================================================================

/// AES-256-GCM encryption/decryption context
///
/// This struct provides both one-shot and streaming APIs for AES-GCM operations.
/// The streaming API allows processing data in chunks, which is useful for:
/// - Large files that don't fit in memory
/// - Network protocols with incremental data
/// - Memory-constrained environments
pub struct Aes256Gcm {
    aes: Aes256,
    ghash_key: GhashKey,
}

impl Aes256Gcm {
    /// Create a new AES-256-GCM context with the given key
    pub fn new(key: &[u8; 32]) -> Self {
        let aes = Aes256::new(key);
        let ghash_key = GhashKey::new(&aes);
        Self { aes, ghash_key }
    }

    /// Encrypt plaintext with associated data
    ///
    /// Returns ciphertext || 16-byte tag
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let j0 = derive_j0(nonce);

        // Encrypt plaintext
        let mut ciphertext = plaintext.to_vec();
        aes_ctr_gcm(&self.aes, &j0, &mut ciphertext);

        // Compute GHASH over AAD and ciphertext
        let mut ghash = GhashState::new(self.ghash_key.clone());
        ghash.update_aad(aad);
        ghash.update_ct(&ciphertext);
        let s = ghash.finalize();

        // Compute tag: T = E_K(J0) XOR S
        let ek_j0 = self.aes.encrypt_block(&j0);
        let s_block = u128_to_block(s);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = ek_j0[i] ^ s_block[i];
        }

        // Append tag to ciphertext
        ciphertext.extend_from_slice(&tag);
        ciphertext
    }

    /// Decrypt ciphertext with associated data
    ///
    /// Input: ciphertext || 16-byte tag
    /// Returns plaintext on success, error on authentication failure
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], ciphertext_and_tag: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext_and_tag.len() < TAG_SIZE {
            return Err("ciphertext too short");
        }

        let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
        let (ciphertext, tag) = ciphertext_and_tag.split_at(ct_len);

        let j0 = derive_j0(nonce);

        // Compute expected GHASH
        let mut ghash = GhashState::new(self.ghash_key.clone());
        ghash.update_aad(aad);
        ghash.update_ct(ciphertext);
        let s = ghash.finalize();

        // Compute expected tag
        let ek_j0 = self.aes.encrypt_block(&j0);
        let s_block = u128_to_block(s);
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = ek_j0[i] ^ s_block[i];
        }

        // Constant-time tag verification
        let tag_array: [u8; 16] = tag.try_into().map_err(|_| "invalid tag length")?;
        if !ct_eq_16(&expected_tag, &tag_array) {
            return Err("authentication failed");
        }

        // Decrypt ciphertext
        let mut plaintext = ciphertext.to_vec();
        aes_ctr_gcm(&self.aes, &j0, &mut plaintext);

        Ok(plaintext)
    }

    /// Encrypt data in-place and return the authentication tag
    ///
    /// The buffer is modified in-place to contain the ciphertext.
    pub fn encrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let j0 = derive_j0(nonce);

        // Encrypt in-place
        aes_ctr_gcm(&self.aes, &j0, buffer);

        // Compute GHASH
        let mut ghash = GhashState::new(self.ghash_key.clone());
        ghash.update_aad(aad);
        ghash.update_ct(buffer);
        let s = ghash.finalize();

        // Compute tag
        let ek_j0 = self.aes.encrypt_block(&j0);
        let s_block = u128_to_block(s);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = ek_j0[i] ^ s_block[i];
        }

        tag
    }

    /// Decrypt data in-place after verifying the authentication tag
    ///
    /// Returns Ok(()) on successful authentication, Err on failure.
    /// The buffer is only modified if authentication succeeds.
    pub fn decrypt_in_place(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8], tag: &[u8; 16]) -> Result<(), &'static str> {
        let j0 = derive_j0(nonce);

        // Compute expected GHASH over ciphertext
        let mut ghash = GhashState::new(self.ghash_key.clone());
        ghash.update_aad(aad);
        ghash.update_ct(buffer);
        let s = ghash.finalize();

        // Compute expected tag
        let ek_j0 = self.aes.encrypt_block(&j0);
        let s_block = u128_to_block(s);
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = ek_j0[i] ^ s_block[i];
        }

        // Constant-time verification
        if !ct_eq_16(&expected_tag, tag) {
            return Err("authentication failed");
        }

        // Decrypt in-place
        aes_ctr_gcm(&self.aes, &j0, buffer);

        Ok(())
    }
}

// ============================================================================
// API FUNCTIONS
// ============================================================================

/// Encrypt plaintext using AES-256-GCM
///
/// # Arguments
/// * `key` - 256-bit encryption key
/// * `nonce` - 96-bit nonce (MUST be unique for each encryption with same key)
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
/// * `plaintext` - Data to encrypt
///
/// # Returns
/// Ciphertext concatenated with 16-byte authentication tag
///
/// # Security Warning
/// Never reuse a nonce with the same key. This completely breaks GCM security.
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let gcm = Aes256Gcm::new(key);
    Ok(gcm.encrypt(nonce, aad, plaintext))
}

/// Decrypt ciphertext using AES-256-GCM
///
/// # Arguments
/// * `key` - 256-bit encryption key
/// * `nonce` - 96-bit nonce (same nonce used for encryption)
/// * `aad` - Additional authenticated data (same AAD used for encryption)
/// * `ciphertext_and_tag` - Ciphertext concatenated with 16-byte authentication tag
///
/// # Returns
/// Plaintext on successful authentication, error on tag mismatch
///
/// # Security
/// This function performs constant-time tag verification to prevent timing attacks.
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let gcm = Aes256Gcm::new(key);
    gcm.decrypt(nonce, aad, ciphertext_and_tag)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // NIST SP 800-38D Test Vectors (Official, with known expected values)
    // Source: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip
    // ========================================================================

    /// NIST Test Case 13: AES-256, empty PT, empty AAD
    /// Key: all zeros (32 bytes)
    /// IV: all zeros (12 bytes)
    /// PT: empty, AAD: empty
    /// Expected Tag: 530f8afbc74536b9a963b4f1c4cb738b
    #[test]
    fn test_nist_case_13_empty() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let pt: &[u8] = &[];

        // NIST expected tag for this test case
        let expected_tag: [u8; 16] = [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
            0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
        ];

        let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), 16); // Only tag, no ciphertext
        assert_eq!(&ct[..], &expected_tag[..], "Tag mismatch for NIST Test Case 13");

        // Verify decryption works
        let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec.len(), 0);
    }

    /// NIST Test Case 14: AES-256, 16-byte PT (all zeros), empty AAD
    /// Key: all zeros (32 bytes)
    /// IV: all zeros (12 bytes)
    /// PT: all zeros (16 bytes), AAD: empty
    /// Expected CT: cea7403d4d606b6e074ec5d3baf39d18
    /// Expected Tag: d0d1c8a799996bf0265b98b5d48ab919
    #[test]
    fn test_nist_case_14_one_block() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let pt = [0u8; 16];

        // NIST expected values
        let expected_ct: [u8; 16] = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
            0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        ];
        let expected_tag: [u8; 16] = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
            0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
        ];

        let result = aes256_gcm_encrypt(&key, &nonce, aad, &pt).unwrap();
        assert_eq!(result.len(), 32); // 16 bytes CT + 16 bytes tag

        let ct = &result[..16];
        let tag = &result[16..];
        assert_eq!(ct, &expected_ct[..], "Ciphertext mismatch for NIST Test Case 14");
        assert_eq!(tag, &expected_tag[..], "Tag mismatch for NIST Test Case 14");

        // Verify decryption
        let dec = aes256_gcm_decrypt(&key, &nonce, aad, &result).unwrap();
        assert_eq!(dec, pt);
    }

    /// NIST Test Case 16: AES-256, 60-byte PT, 20-byte AAD
    /// Key: feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
    /// IV: cafebabefacedbaddecaf888
    /// AAD: feedfacedeadbeeffeedfacedeadbeefabaddad2
    /// PT: d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
    ///     1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
    /// Expected CT: 522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
    ///              8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662
    /// Expected Tag: 76fc6ece0f4e1768cddf8853bb2d551b
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

        // NIST expected values
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
        assert_eq!(result.len(), 76); // 60 bytes CT + 16 bytes tag

        let ct = &result[..60];
        let tag = &result[60..];
        assert_eq!(ct, &expected_ct[..], "Ciphertext mismatch for NIST Test Case 16");
        assert_eq!(tag, &expected_tag[..], "Tag mismatch for NIST Test Case 16");

        // Verify decryption
        let dec = aes256_gcm_decrypt(&key, &nonce, &aad, &result).unwrap();
        assert_eq!(dec, pt);
    }

    /// Test Case 3: With AAD
    #[test]
    fn test_with_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"additional authenticated data";
        let pt = b"secret message to encrypt";

        let ct = aes256_gcm_encrypt(&key, &nonce, aad, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 16);

        // Correct decryption
        let dec = aes256_gcm_decrypt(&key, &nonce, aad, &ct).unwrap();
        assert_eq!(dec, pt);

        // Modified AAD should fail
        let bad_aad = b"modified authenticated data!!";
        let result = aes256_gcm_decrypt(&key, &nonce, bad_aad, &ct);
        assert!(result.is_err());

        // Modified ciphertext should fail
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        let result = aes256_gcm_decrypt(&key, &nonce, aad, &bad_ct);
        assert!(result.is_err());

        // Modified tag should fail
        let mut bad_tag = ct.clone();
        let tag_start = bad_tag.len() - 16;
        bad_tag[tag_start] ^= 1;
        let result = aes256_gcm_decrypt(&key, &nonce, aad, &bad_tag);
        assert!(result.is_err());
    }

    /// Test Case 4: Large plaintext (multiple blocks)
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

    /// Test Case 5: In-place encryption/decryption
    #[test]
    fn test_in_place() {
        let key = [0x12u8; 32];
        let nonce = [0x34u8; 12];
        let aad = b"aad";
        let original = b"plaintext data here";

        let gcm = Aes256Gcm::new(&key);

        // Encrypt in-place
        let mut buffer = original.to_vec();
        let tag = gcm.encrypt_in_place(&nonce, aad, &mut buffer);

        // Buffer now contains ciphertext
        assert_ne!(&buffer[..], original);

        // Decrypt in-place
        gcm.decrypt_in_place(&nonce, aad, &mut buffer, &tag).unwrap();
        assert_eq!(&buffer[..], original);
    }

    /// Test Case 6: GF(2^128) multiplication correctness
    #[test]
    fn test_gf128_mul() {
        // Test that 0 * anything = 0
        let zero = (0u64, 0u64);
        let x = (0x1234567890ABCDEFu64, 0xFEDCBA0987654321u64);
        assert_eq!(gf128_mul_bitwise(zero, x), zero);
        assert_eq!(gf128_mul_bitwise(x, zero), zero);

        // Test that 1 * x = x (where 1 is the MSB set)
        // In GF(2^128) with our representation, "1" is (0x8000_0000_0000_0000, 0)
        let one = (0x8000_0000_0000_0000u64, 0u64);
        let y = (0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64);
        assert_eq!(gf128_mul_bitwise(one, y), y);
    }

    /// Test Case 7: Verify tag changes with different nonces
    #[test]
    fn test_nonce_affects_tag() {
        let key = [0x55u8; 32];
        let nonce1 = [0x00u8; 12];
        let nonce2 = [0x01u8; 12];
        let aad = b"same aad";
        let pt = b"same plaintext";

        let ct1 = aes256_gcm_encrypt(&key, &nonce1, aad, pt).unwrap();
        let ct2 = aes256_gcm_encrypt(&key, &nonce2, aad, pt).unwrap();

        // Ciphertexts should be different
        assert_ne!(ct1, ct2);

        // Both should decrypt correctly with correct nonce
        assert_eq!(aes256_gcm_decrypt(&key, &nonce1, aad, &ct1).unwrap(), pt);
        assert_eq!(aes256_gcm_decrypt(&key, &nonce2, aad, &ct2).unwrap(), pt);

        // Cross-decryption should fail
        assert!(aes256_gcm_decrypt(&key, &nonce1, aad, &ct2).is_err());
        assert!(aes256_gcm_decrypt(&key, &nonce2, aad, &ct1).is_err());
    }

    /// Test Case 8: Edge case - exactly one block
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

    /// Test Case 9: Edge case - partial block
    #[test]
    fn test_partial_block() {
        let key = [0xAAu8; 32];
        let nonce = [0xBBu8; 12];
        let aad = [0xCCu8; 7]; // Partial AAD block
        let pt = [0xDDu8; 13]; // Partial PT block

        let ct = aes256_gcm_encrypt(&key, &nonce, &aad, &pt).unwrap();
        let dec = aes256_gcm_decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(dec, pt);
    }

    /// Test decryption with truncated ciphertext fails
    #[test]
    fn test_truncated_ciphertext() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        // Too short (less than tag size)
        let result = aes256_gcm_decrypt(&key, &nonce, &[], &[0u8; 15]);
        assert!(result.is_err());
    }
}
