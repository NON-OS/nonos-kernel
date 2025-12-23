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
//!
//! AES-128 and AES-256 block ciphers with constant-time
//! operations to prevent cache-timing side-channel attacks.
//!
//! # Security Properties
//!
//! - **Constant-time S-box lookups**: Uses full table scan to prevent
//!   cache-timing attacks. Every lookup accesses all 256 table entries.
//! - **Constant-time GF multiplication**: GF(2^8) multiplication for MixColumns.
//! - **Secure key erasure**: Round keys are securely zeroed on drop.
//!
//! # Performance Notes
//!
//! This is a pure software implementation optimized for security over speed.
//! On platforms with AES-NI instructions, a hardware-accelerated implementation
//! would be significantly faster while also providing inherent side-channel
//! resistance.
//!
//! # Supported Key Sizes
//!
//! - AES-128: 128-bit key (16 bytes), 10 rounds
//! - AES-256: 256-bit key (32 bytes), 14 rounds
//! # References
//!
//! - FIPS 197: Advanced Encryption Standard (AES)
//! - NIST SP 800-38A: Recommendation for Block Cipher Modes of Operation

use super::constant_time::{ct_lookup_u8, secure_zero, compiler_fence};

// ============================================================================
// CONSTANTS
// ============================================================================

/// AES block size in bytes (128 bits)
pub const BLOCK_SIZE: usize = 16;

/// AES-128 key size in bytes
pub const AES128_KEY_SIZE: usize = 16;

/// AES-256 key size in bytes
pub const AES256_KEY_SIZE: usize = 32;

/// Number of rounds for AES-128
const AES128_ROUNDS: usize = 10;

/// Number of rounds for AES-256
const AES256_ROUNDS: usize = 14;

/// Round constants for key expansion (sufficient for both AES-128 and AES-256)
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

// ============================================================================
// AES-256
// ============================================================================

/// AES-256 block cipher context
///
/// Stores the expanded round keys for encryption and decryption.
/// Round keys are securely erased when the context is dropped.
#[derive(Clone)]
pub struct Aes256 {
    /// 15 round keys (rounds 0-14), each 16 bytes
    round_keys: [[u8; 16]; 15],
}

impl Drop for Aes256 {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            secure_zero(rk);
        }
        compiler_fence();
    }
}

impl Aes256 {
    /// Create a new AES-256 context with the given 256-bit key
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte (256-bit) encryption key
    ///
    /// # Returns
    ///
    /// A new `Aes256` context ready for encryption/decryption
    pub fn new(key: &[u8; 32]) -> Self {
        let mut aes = Self { round_keys: [[0u8; 16]; 15] };
        aes.expand_key(key);
        aes
    }

    /// Expand the 256-bit key into round keys
    ///
    /// AES-256 key schedule: Nk=8, Nb=4, Nr=14
    /// Generates 60 words (240 bytes) = 15 round keys
    fn expand_key(&mut self, key: &[u8; 32]) {
        // 60 words for AES-256: 4 * (Nr + 1) = 4 * 15 = 60
        let mut w = [0u32; 60];

        // Copy initial key (8 words)
        for i in 0..8 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        }

        // Expand key schedule
        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                // Apply RotWord, SubWord, and XOR with Rcon
                temp = sub_word_ct(rot_word(temp)) ^ u32::from_be_bytes([RCON[i / 8 - 1], 0, 0, 0]);
            } else if i % 8 == 4 {
                // Extra SubWord for AES-256
                temp = sub_word_ct(temp);
            }
            w[i] = w[i - 8] ^ temp;
        }

        // Pack words into round keys
        for r in 0..15 {
            let base = r * 4;
            self.round_keys[r][0..4].copy_from_slice(&w[base].to_be_bytes());
            self.round_keys[r][4..8].copy_from_slice(&w[base + 1].to_be_bytes());
            self.round_keys[r][8..12].copy_from_slice(&w[base + 2].to_be_bytes());
            self.round_keys[r][12..16].copy_from_slice(&w[base + 3].to_be_bytes());
        }

        // Securely erase temporary key schedule
        for word in &mut w {
            *word = 0;
        }
        compiler_fence();
    }

    /// Encrypt a single 128-bit block
    ///
    /// # Arguments
    ///
    /// * `plaintext` - 16-byte plaintext block
    ///
    /// # Returns
    ///
    /// 16-byte ciphertext block
    pub fn encrypt_block(&self, plaintext: &[u8; 16]) -> [u8; 16] {
        let mut state = *plaintext;

        // Initial round key addition
        add_round_key(&mut state, &self.round_keys[0]);

        // Main rounds (1 through Nr-1)
        for round in 1..AES256_ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
        }

        // Final round (no MixColumns)
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[AES256_ROUNDS]);

        state
    }

    /// Decrypt a single 128-bit block
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - 16-byte ciphertext block
    ///
    /// # Returns
    ///
    /// 16-byte plaintext block
    pub fn decrypt_block(&self, ciphertext: &[u8; 16]) -> [u8; 16] {
        let mut state = *ciphertext;

        // Initial round key addition (last round key)
        add_round_key(&mut state, &self.round_keys[AES256_ROUNDS]);

        // Main rounds in reverse (Nr-1 through 1)
        for round in (1..AES256_ROUNDS).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
            inv_mix_columns(&mut state);
        }

        // Final round (no InvMixColumns)
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &self.round_keys[0]);

        state
    }

    /// AES-CTR mode encryption/decryption
    ///
    /// CTR mode uses AES to generate a keystream that is XORed with the data.
    /// Encryption and decryption are the same operation.
    ///
    /// # Arguments
    ///
    /// * `nonce_counter` - 16-byte nonce/counter block (modified in place)
    /// * `data` - Data to encrypt/decrypt in place
    ///
    /// # Note
    ///
    /// The counter is incremented as a big-endian 128-bit integer.
    /// For GCM mode, use the separate inc32 function which only
    /// increments the last 32 bits.
    pub fn ctr_apply(&self, nonce_counter: &mut [u8; 16], data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let keystream = self.encrypt_block(nonce_counter);
            let chunk = (data.len() - offset).min(16);
            for i in 0..chunk {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk;
            increment_be128(nonce_counter);
        }
    }
}

// ============================================================================
// AES-128
// ============================================================================

/// AES-128 block cipher context
///
/// Stores the expanded round keys for encryption and decryption.
/// Round keys are securely erased when the context is dropped.
#[derive(Clone)]
pub struct Aes128 {
    /// 11 round keys (rounds 0-10), each 16 bytes
    round_keys: [[u8; 16]; 11],
}

impl Drop for Aes128 {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            secure_zero(rk);
        }
        compiler_fence();
    }
}

impl Aes128 {
    /// Create a new AES-128 context with the given 128-bit key
    ///
    /// # Arguments
    ///
    /// * `key` - 16-byte (128-bit) encryption key
    ///
    /// # Returns
    ///
    /// A new `Aes128` context ready for encryption/decryption
    pub fn new(key: &[u8; 16]) -> Self {
        let mut aes = Self { round_keys: [[0u8; 16]; 11] };
        aes.expand_key(key);
        aes
    }

    /// Expand the 128-bit key into round keys
    ///
    /// AES-128 key schedule: Nk=4, Nb=4, Nr=10
    /// Generates 44 words (176 bytes) = 11 round keys
    fn expand_key(&mut self, key: &[u8; 16]) {
        // 44 words for AES-128: 4 * (Nr + 1) = 4 * 11 = 44
        let mut w = [0u32; 44];

        // Copy initial key (4 words)
        for i in 0..4 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([key[j], key[j + 1], key[j + 2], key[j + 3]]);
        }

        // Expand key schedule
        for i in 4..44 {
            let mut temp = w[i - 1];
            if i % 4 == 0 {
                // Apply RotWord, SubWord, and XOR with Rcon
                temp = sub_word_ct(rot_word(temp)) ^ u32::from_be_bytes([RCON[i / 4 - 1], 0, 0, 0]);
            }
            w[i] = w[i - 4] ^ temp;
        }

        // Pack words into round keys
        for r in 0..11 {
            let base = r * 4;
            self.round_keys[r][0..4].copy_from_slice(&w[base].to_be_bytes());
            self.round_keys[r][4..8].copy_from_slice(&w[base + 1].to_be_bytes());
            self.round_keys[r][8..12].copy_from_slice(&w[base + 2].to_be_bytes());
            self.round_keys[r][12..16].copy_from_slice(&w[base + 3].to_be_bytes());
        }

        // Securely erase temporary key schedule
        for word in &mut w {
            *word = 0;
        }
        compiler_fence();
    }

    /// Encrypt a single 128-bit block
    ///
    /// # Arguments
    ///
    /// * `plaintext` - 16-byte plaintext block
    ///
    /// # Returns
    ///
    /// 16-byte ciphertext block
    pub fn encrypt_block(&self, plaintext: &[u8; 16]) -> [u8; 16] {
        let mut state = *plaintext;

        // Initial round key addition
        add_round_key(&mut state, &self.round_keys[0]);

        // Main rounds (1 through Nr-1)
        for round in 1..AES128_ROUNDS {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
        }

        // Final round (no MixColumns)
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[AES128_ROUNDS]);

        state
    }

    /// Decrypt a single 128-bit block
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - 16-byte ciphertext block
    ///
    /// # Returns
    ///
    /// 16-byte plaintext block
    pub fn decrypt_block(&self, ciphertext: &[u8; 16]) -> [u8; 16] {
        let mut state = *ciphertext;

        // Initial round key addition (last round key)
        add_round_key(&mut state, &self.round_keys[AES128_ROUNDS]);

        // Main rounds in reverse (Nr-1 through 1)
        for round in (1..AES128_ROUNDS).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &self.round_keys[round]);
            inv_mix_columns(&mut state);
        }

        // Final round (no InvMixColumns)
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &self.round_keys[0]);

        state
    }

    /// AES-CTR mode encryption/decryption
    ///
    /// CTR mode uses AES to generate a keystream that is XORed with the data.
    /// Encryption and decryption are the same operation.
    ///
    /// # Arguments
    ///
    /// * `nonce_counter` - 16-byte nonce/counter block (modified in place)
    /// * `data` - Data to encrypt/decrypt in place
    pub fn ctr_apply(&self, nonce_counter: &mut [u8; 16], data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let keystream = self.encrypt_block(nonce_counter);
            let chunk = (data.len() - offset).min(16);
            for i in 0..chunk {
                data[offset + i] ^= keystream[i];
            }
            offset += chunk;
            increment_be128(nonce_counter);
        }
    }
}

// ============================================================================
// CORE AES OPERATIONS
// ============================================================================

/// AddRoundKey: XOR state with round key
#[inline]
fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

/// SubBytes: Apply S-box to each byte (constant-time)
///
/// Uses full table scan to prevent cache-timing attacks.
/// Marked `#[inline(never)]` to prevent the compiler from
/// optimizing away the constant-time properties.
#[inline(never)]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = ct_lookup_u8(&SBOX, *b);
    }
}

/// InvSubBytes: Apply inverse S-box to each byte (constant-time)
#[inline(never)]
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = ct_lookup_u8(&INV_SBOX, *b);
    }
}

/// ShiftRows: Cyclically shift rows of the state
///
/// Row 0: no shift
/// Row 1: shift left by 1
/// Row 2: shift left by 2
/// Row 3: shift left by 3
///
/// State layout (column-major):
/// ```text
/// s[0]  s[4]  s[8]  s[12]   (row 0)
/// s[1]  s[5]  s[9]  s[13]   (row 1)
/// s[2]  s[6]  s[10] s[14]   (row 2)
/// s[3]  s[7]  s[11] s[15]   (row 3)
/// ```
#[inline]
fn shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift left by 1
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    // Row 2: shift left by 2
    let (t1, t2) = (state[2], state[6]);
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t1;
    state[14] = t2;

    // Row 3: shift left by 3 (same as right by 1)
    let t = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t;
}

/// InvShiftRows: Inverse of ShiftRows
#[inline]
fn inv_shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift right by 1
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;

    // Row 2: shift right by 2 (same as left by 2)
    let (t1, t2) = (state[2], state[6]);
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t1;
    state[14] = t2;

    // Row 3: shift right by 3 (same as left by 1)
    let t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
}

/// MixColumns: Mix bytes within each column
///
/// Each column is treated as a polynomial over GF(2^8)
/// and multiplied by the fixed polynomial {03}x^3 + {01}x^2 + {01}x + {02}
#[inline]
fn mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];

        state[i]     = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

/// InvMixColumns: Inverse of MixColumns
///
/// Multiplied by the inverse polynomial {0b}x^3 + {0d}x^2 + {09}x + {0e}
#[inline]
fn inv_mix_columns(state: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];

        state[i]     = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        state[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        state[i + 2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        state[i + 3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

// ============================================================================
// GF(2^8) ARITHMETIC
// ============================================================================

/// Constant-time multiplication in GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1
///
/// This implementation is fully unrolled and branchless to prevent timing attacks.
/// Every execution path takes the same amount of time regardless of input values.
#[inline(always)]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut res: u8 = 0;
    let mut aa = a;

    // Unrolled loop for 8 iterations
    // Each iteration: conditionally add aa to result, then double aa in GF(2^8)

    // Bit 0
    let mask = 0u8.wrapping_sub((b >> 0) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 1
    let mask = 0u8.wrapping_sub((b >> 1) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 2
    let mask = 0u8.wrapping_sub((b >> 2) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 3
    let mask = 0u8.wrapping_sub((b >> 3) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 4
    let mask = 0u8.wrapping_sub((b >> 4) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 5
    let mask = 0u8.wrapping_sub((b >> 5) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 6
    let mask = 0u8.wrapping_sub((b >> 6) & 1);
    res ^= mask & aa;
    let carry = (aa >> 7) & 1;
    aa = (aa << 1) ^ (0x1B & 0u8.wrapping_sub(carry));

    // Bit 7 (final, no need to update aa)
    let mask = 0u8.wrapping_sub((b >> 7) & 1);
    res ^= mask & aa;

    res
}

// ============================================================================
// KEY SCHEDULE HELPERS
// ============================================================================

/// RotWord: Rotate a 32-bit word left by 8 bits
#[inline]
fn rot_word(x: u32) -> u32 {
    (x << 8) | (x >> 24)
}

/// SubWord: Apply S-box to each byte of a 32-bit word (constant-time)
///
/// Marked `#[inline(never)]` to prevent optimizer from breaking constant-time.
#[inline(never)]
fn sub_word_ct(x: u32) -> u32 {
    let b = x.to_be_bytes();
    let y = [
        ct_lookup_u8(&SBOX, b[0]),
        ct_lookup_u8(&SBOX, b[1]),
        ct_lookup_u8(&SBOX, b[2]),
        ct_lookup_u8(&SBOX, b[3]),
    ];
    u32::from_be_bytes(y)
}

/// Increment a 128-bit big-endian counter
#[inline]
fn increment_be128(v: &mut [u8; 16]) {
    for i in (0..16).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            break;
        }
    }
}

// ============================================================================
// S-BOXES
// ============================================================================

/// AES S-box (SubBytes transformation)
///
/// S-box[x] = affine(inverse(x)) where:
/// - inverse(x) is the multiplicative inverse in GF(2^8)
/// - affine is a fixed affine transformation
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES Inverse S-box (InvSubBytes transformation)
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // ========================================================================
    // AES-256 Test Vectors (FIPS-197 Appendix C.3 and NIST SP 800-38A)
    // ========================================================================

    /// NIST SP 800-38A F.1.5: AES-256 ECB Test Vector
    #[test]
    fn test_aes256_nist_sp800_38a() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected_ct: [u8; 16] = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
        ];

        let aes = Aes256::new(&key);
        let ciphertext = aes.encrypt_block(&plaintext);
        assert_eq!(ciphertext, expected_ct);

        let decrypted = aes.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// FIPS-197 Appendix C.3: AES-256 Test Vector
    #[test]
    fn test_aes256_fips197_appendix_c3() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];

        let aes = Aes256::new(&key);
        let ciphertext = aes.encrypt_block(&plaintext);
        assert_eq!(ciphertext, expected_ct);

        let decrypted = aes.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Test AES-256 with all-zero key and plaintext
    #[test]
    fn test_aes256_zero_key_plaintext() {
        let key = [0u8; 32];
        let plaintext = [0u8; 16];

        let aes = Aes256::new(&key);
        let ciphertext = aes.encrypt_block(&plaintext);

        // Ciphertext should not be all zeros
        assert_ne!(ciphertext, [0u8; 16]);

        let decrypted = aes.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Test AES-256 CTR mode roundtrip
    #[test]
    fn test_aes256_ctr_roundtrip() {
        let key = [0x42u8; 32];
        let mut ctr = [0u8; 16];
        ctr[15] = 1;

        let original: Vec<u8> = (0..100).collect();
        let mut data = original.clone();

        let aes = Aes256::new(&key);
        aes.ctr_apply(&mut ctr.clone(), &mut data);

        // Data should be encrypted (different from original)
        assert_ne!(data, original);

        // Decrypt by applying CTR again
        let mut ctr2 = [0u8; 16];
        ctr2[15] = 1;
        aes.ctr_apply(&mut ctr2, &mut data);

        assert_eq!(data, original);
    }

    // ========================================================================
    // AES-128 Test Vectors (FIPS-197 Appendix C.1 and NIST SP 800-38A)
    // ========================================================================

    /// NIST SP 800-38A F.1.1: AES-128 ECB Test Vector
    #[test]
    fn test_aes128_nist_sp800_38a() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        let expected_ct: [u8; 16] = [
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        ];

        let aes = Aes128::new(&key);
        let ciphertext = aes.encrypt_block(&plaintext);
        assert_eq!(ciphertext, expected_ct);

        let decrypted = aes.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// FIPS-197 Appendix C.1: AES-128 Test Vector
    #[test]
    fn test_aes128_fips197_appendix_c1() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected_ct: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
            0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
        ];

        let aes = Aes128::new(&key);
        let ciphertext = aes.encrypt_block(&plaintext);
        assert_eq!(ciphertext, expected_ct);

        let decrypted = aes.decrypt_block(&ciphertext);
        assert_eq!(decrypted, plaintext);
    }

    /// Test AES-128 CTR mode roundtrip
    #[test]
    fn test_aes128_ctr_roundtrip() {
        let key = [0x55u8; 16];
        let mut ctr = [0u8; 16];
        ctr[15] = 1;

        let original: Vec<u8> = (0..64).collect();
        let mut data = original.clone();

        let aes = Aes128::new(&key);
        aes.ctr_apply(&mut ctr.clone(), &mut data);

        // Decrypt
        let mut ctr2 = [0u8; 16];
        ctr2[15] = 1;
        aes.ctr_apply(&mut ctr2, &mut data);

        assert_eq!(data, original);
    }

    // ========================================================================
    // GF(2^8) Arithmetic Tests
    // ========================================================================

    /// Test GF multiplication identity: a * 1 = a
    #[test]
    fn test_gf_mul_identity() {
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
        }
    }

    /// Test GF multiplication with zero: a * 0 = 0
    #[test]
    fn test_gf_mul_zero() {
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(0, a), 0);
        }
    }

    /// Test known GF(2^8) multiplication results
    #[test]
    fn test_gf_mul_known_values() {
        // 0x57 * 0x83 = 0xc1 (from FIPS-197)
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);

        // 0x57 * 0x02 = 0xae
        assert_eq!(gf_mul(0x57, 0x02), 0xae);

        // 0x57 * 0x04 = 0x47
        assert_eq!(gf_mul(0x57, 0x04), 0x47);
    }

    /// Test GF multiplication commutativity: a * b = b * a
    #[test]
    fn test_gf_mul_commutative() {
        let test_values = [0x00, 0x01, 0x02, 0x03, 0x53, 0xCA, 0xFE, 0xFF];
        for &a in &test_values {
            for &b in &test_values {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
            }
        }
    }

    // ========================================================================
    // S-box Tests
    // ========================================================================

    /// Verify S-box and inverse S-box are inverses of each other
    #[test]
    fn test_sbox_inverse() {
        for i in 0..=255u8 {
            let s = ct_lookup_u8(&SBOX, i);
            let inv = ct_lookup_u8(&INV_SBOX, s);
            assert_eq!(inv, i, "INV_SBOX[SBOX[{}]] != {}", i, i);
        }
    }

    /// Known S-box values
    #[test]
    fn test_sbox_known_values() {
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7c);
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(SBOX[0xff], 0x16);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    /// Test CTR mode with empty data
    #[test]
    fn test_ctr_empty_data() {
        let key = [0u8; 32];
        let mut ctr = [0u8; 16];
        let mut data: [u8; 0] = [];

        let aes = Aes256::new(&key);
        aes.ctr_apply(&mut ctr, &mut data);

        // Counter should not change
        assert_eq!(ctr, [0u8; 16]);
    }

    /// Test CTR mode with single byte
    #[test]
    fn test_ctr_single_byte() {
        let key = [0u8; 32];
        let mut ctr = [0u8; 16];
        ctr[15] = 1;
        let mut data = [0x42u8];

        let aes = Aes256::new(&key);
        aes.ctr_apply(&mut ctr.clone(), &mut data);

        // Should be encrypted
        assert_ne!(data[0], 0x42);

        // Decrypt
        let mut ctr2 = [0u8; 16];
        ctr2[15] = 1;
        aes.ctr_apply(&mut ctr2, &mut data);
        assert_eq!(data[0], 0x42);
    }

    /// Test counter increment wrapping
    #[test]
    fn test_counter_increment() {
        let mut ctr = [0xffu8; 16];
        increment_be128(&mut ctr);
        assert_eq!(ctr, [0u8; 16]); // Should wrap to all zeros
    }
}
