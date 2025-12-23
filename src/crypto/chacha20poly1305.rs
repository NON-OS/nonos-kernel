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
//! ChaCha20-Poly1305 AEAD (RFC 8439)
//! Authenticated Encryption with Associated Data (AEAD) construction.
//!
//! # Features
//!
//! - **ChaCha20**: 256-bit key, 96-bit nonce stream cipher
//! - **Poly1305**: One-time authenticator for message integrity
//! - **AEAD**: Combined encryption and authentication
//! - **RFC 8439 compliant**: Passes all official test vectors
//!
//! # Security
//!
//! - 256-bit security level
//! - Constant-time tag comparison
//! - Secure zeroing of sensitive data
//! - Nonce must NEVER be reused with the same key

extern crate alloc;

use alloc::vec::Vec;
use crate::crypto::constant_time::{ct_eq, compiler_fence};

// ============================================================================
// CONSTANTS
// ============================================================================

/// ChaCha20 block size in bytes
pub const CHACHA20_BLOCK_SIZE: usize = 64;

/// ChaCha20 key size in bytes
pub const KEY_SIZE: usize = 32;

/// ChaCha20 nonce size in bytes (96-bit as per RFC 8439)
pub const NONCE_SIZE: usize = 12;

/// Poly1305 tag size in bytes
pub const TAG_SIZE: usize = 16;

/// ChaCha20 "expand 32-byte k" constant
const CHACHA_CONSTANT: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

// ============================================================================
// SECURE ZEROING
// ============================================================================

/// Securely zero a byte slice using volatile writes
#[inline]
fn secure_zero_bytes(buf: &mut [u8]) {
    for b in buf {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    compiler_fence();
}

/// Securely zero a u32 slice using volatile writes
#[inline]
fn secure_zero_u32(buf: &mut [u32]) {
    for w in buf {
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    compiler_fence();
}

// ============================================================================
// CHACHA20 STREAM CIPHER
// ============================================================================

/// ChaCha20 quarter round
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate a single ChaCha20 block
///
/// # Arguments
/// * `key` - 256-bit key
/// * `nonce` - 96-bit nonce
/// * `counter` - 32-bit block counter
/// * `out` - Output buffer (64 bytes)
pub fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8; 64]) {
    // Initialize state
    let mut state = [0u32; 16];

    // Constants
    state[0] = CHACHA_CONSTANT[0];
    state[1] = CHACHA_CONSTANT[1];
    state[2] = CHACHA_CONSTANT[2];
    state[3] = CHACHA_CONSTANT[3];

    // Key (8 words)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }

    // Counter
    state[12] = counter;

    // Nonce (3 words)
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    // Copy initial state for final addition
    let initial = state;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state and serialize to output
    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
}

/// Apply ChaCha20 keystream XOR to data
///
/// This is the core encryption/decryption operation.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut block = [0u8; 64];
    let mut block_counter = counter;
    let mut offset = 0;

    while offset < data.len() {
        chacha20_block(key, nonce, block_counter, &mut block);

        let remaining = data.len() - offset;
        let to_xor = core::cmp::min(64, remaining);

        for i in 0..to_xor {
            data[offset + i] ^= block[i];
        }

        offset += to_xor;
        block_counter = block_counter.wrapping_add(1);
    }

    secure_zero_bytes(&mut block);
}

// ============================================================================
// POLY1305 ONE-TIME AUTHENTICATOR
// ============================================================================

/// Poly1305 state using 26-bit radix representation
///
/// The accumulator h and key r are represented as 5 limbs of 26 bits each,
/// allowing efficient modular arithmetic without 128-bit integers.
struct Poly1305 {
    // Accumulator limbs
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    // Key r limbs (clamped)
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    // Precomputed 5*r values for modular reduction
    s1: u32,
    s2: u32,
    s3: u32,
    s4: u32,
    // Key s (second half, added at the end)
    s: [u8; 16],
    // Buffer for partial blocks
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    /// Create a new Poly1305 instance with the given 32-byte key
    fn new(key: &[u8; 32]) -> Self {
        // Load r from first 16 bytes and clamp
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[0..16]);

        // Clamp r: clear bits as per RFC 8439
        r[3] &= 0x0f;   // Clear top 4 bits
        r[7] &= 0x0f;
        r[11] &= 0x0f;
        r[15] &= 0x0f;
        r[4] &= 0xfc;   // Clear bottom 2 bits
        r[8] &= 0xfc;
        r[12] &= 0xfc;

        // Convert r to 26-bit limbs using donna-style extraction
        let t0 = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        let t1 = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
        let t2 = u32::from_le_bytes([r[8], r[9], r[10], r[11]]);
        let t3 = u32::from_le_bytes([r[12], r[13], r[14], r[15]]);

        let r0 = t0 & 0x3ffffff;
        let r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        let r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        let r3 = ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        let r4 = t3 >> 8;

        // Precompute 5*r for modular reduction (since 2^130 ≡ 5 mod p)
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        // Load s from second 16 bytes
        let mut s = [0u8; 16];
        s.copy_from_slice(&key[16..32]);

        Self {
            h0: 0,
            h1: 0,
            h2: 0,
            h3: 0,
            h4: 0,
            r0,
            r1,
            r2,
            r3,
            r4,
            s1,
            s2,
            s3,
            s4,
            s,
            buffer: [0u8; 16],
            buffer_len: 0,
        }
    }

    /// Process a 16-byte block
    fn block(&mut self, msg: &[u8], hibit: u32) {
        // Convert message block to 26-bit limbs
        let t0 = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let t1 = u32::from_le_bytes([msg[4], msg[5], msg[6], msg[7]]);
        let t2 = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let t3 = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);

        // Add message to accumulator
        self.h0 = self.h0.wrapping_add(t0 & 0x3ffffff);
        self.h1 = self.h1.wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
        self.h2 = self.h2.wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
        self.h3 = self.h3.wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
        self.h4 = self.h4.wrapping_add((t3 >> 8) | hibit);

        // Multiply h by r (mod 2^130 - 5)
        let d0 = (self.h0 as u64) * (self.r0 as u64)
            + (self.h1 as u64) * (self.s4 as u64)
            + (self.h2 as u64) * (self.s3 as u64)
            + (self.h3 as u64) * (self.s2 as u64)
            + (self.h4 as u64) * (self.s1 as u64);

        let d1 = (self.h0 as u64) * (self.r1 as u64)
            + (self.h1 as u64) * (self.r0 as u64)
            + (self.h2 as u64) * (self.s4 as u64)
            + (self.h3 as u64) * (self.s3 as u64)
            + (self.h4 as u64) * (self.s2 as u64);

        let d2 = (self.h0 as u64) * (self.r2 as u64)
            + (self.h1 as u64) * (self.r1 as u64)
            + (self.h2 as u64) * (self.r0 as u64)
            + (self.h3 as u64) * (self.s4 as u64)
            + (self.h4 as u64) * (self.s3 as u64);

        let d3 = (self.h0 as u64) * (self.r3 as u64)
            + (self.h1 as u64) * (self.r2 as u64)
            + (self.h2 as u64) * (self.r1 as u64)
            + (self.h3 as u64) * (self.r0 as u64)
            + (self.h4 as u64) * (self.s4 as u64);

        let d4 = (self.h0 as u64) * (self.r4 as u64)
            + (self.h1 as u64) * (self.r3 as u64)
            + (self.h2 as u64) * (self.r2 as u64)
            + (self.h3 as u64) * (self.r1 as u64)
            + (self.h4 as u64) * (self.r0 as u64);

        // Carry propagation
        let mut c: u32;
        c = (d0 >> 26) as u32;
        self.h0 = (d0 as u32) & 0x3ffffff;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        self.h1 = (d1 as u32) & 0x3ffffff;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        self.h2 = (d2 as u32) & 0x3ffffff;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        self.h3 = (d3 as u32) & 0x3ffffff;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        self.h4 = (d4 as u32) & 0x3ffffff;

        // Reduce: h0 += c * 5 (since 2^130 ≡ 5 mod p)
        self.h0 = self.h0.wrapping_add(c * 5);
        c = self.h0 >> 26;
        self.h0 &= 0x3ffffff;
        self.h1 = self.h1.wrapping_add(c);
    }

    /// Update with arbitrary-length data
    fn update(&mut self, mut data: &[u8]) {
        // If we have buffered data, try to complete the buffer first
        if self.buffer_len > 0 {
            let need = 16 - self.buffer_len;
            let take = core::cmp::min(need, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];

            if self.buffer_len == 16 {
                let buf_copy = self.buffer;
                self.block(&buf_copy, 1 << 24);
                self.buffer_len = 0;
            }
        }

        // Process full 16-byte blocks
        while data.len() >= 16 {
            self.block(&data[..16], 1 << 24); // hibit = 2^128
            data = &data[16..];
        }

        // Buffer remaining partial data (don't process yet)
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    /// Finalize and return the 16-byte tag
    fn finalize(&mut self) -> [u8; 16] {
        // Process any remaining buffered data as partial block
        if self.buffer_len > 0 {
            let mut block = [0u8; 16];
            block[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
            block[self.buffer_len] = 1; // Append 0x01 byte to mark end
            self.block(&block, 0); // No hibit for partial block
        }

        // Final carry propagation
        let mut c = self.h1 >> 26;
        self.h1 &= 0x3ffffff;
        self.h2 = self.h2.wrapping_add(c);
        c = self.h2 >> 26;
        self.h2 &= 0x3ffffff;
        self.h3 = self.h3.wrapping_add(c);
        c = self.h3 >> 26;
        self.h3 &= 0x3ffffff;
        self.h4 = self.h4.wrapping_add(c);
        c = self.h4 >> 26;
        self.h4 &= 0x3ffffff;
        self.h0 = self.h0.wrapping_add(c * 5);
        c = self.h0 >> 26;
        self.h0 &= 0x3ffffff;
        self.h1 = self.h1.wrapping_add(c);

        // Compute h + -p = h - (2^130 - 5) = h + 5 - 2^130
        let mut g0 = self.h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        let mut g1 = self.h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        let mut g2 = self.h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        let mut g3 = self.h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        let g4 = self.h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if h < p, else g (constant-time)
        // If g4 has bit 26 set (negative), use h; otherwise use g
        let mask = ((g4 >> 31) as u32).wrapping_sub(1); // All 1s if g4 >= 0, all 0s if g4 < 0
        let mask = !mask; // Invert: all 1s if g4 < 0 (h < p), all 0s if g4 >= 0 (h >= p)

        self.h0 = (self.h0 & mask) | (g0 & !mask);
        self.h1 = (self.h1 & mask) | (g1 & !mask);
        self.h2 = (self.h2 & mask) | (g2 & !mask);
        self.h3 = (self.h3 & mask) | (g3 & !mask);
        self.h4 = (self.h4 & mask) | (g4 & !mask);

        // Serialize h to 16 bytes
        let h0 = self.h0;
        let h1 = self.h1;
        let h2 = self.h2;
        let h3 = self.h3;
        let h4 = self.h4;

        let mut f = [0u8; 16];
        let t = h0 | (h1 << 26);
        f[0..4].copy_from_slice(&(t as u32).to_le_bytes());
        let t = (h1 >> 6) | (h2 << 20);
        f[4..8].copy_from_slice(&(t as u32).to_le_bytes());
        let t = (h2 >> 12) | (h3 << 14);
        f[8..12].copy_from_slice(&(t as u32).to_le_bytes());
        let t = (h3 >> 18) | (h4 << 8);
        f[12..16].copy_from_slice(&(t as u32).to_le_bytes());

        // Add s (second half of key)
        let mut tag = [0u8; 16];
        let mut carry = 0u16;
        for i in 0..16 {
            let v = f[i] as u16 + self.s[i] as u16 + carry;
            tag[i] = v as u8;
            carry = v >> 8;
        }

        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Zero all sensitive state
        unsafe {
            core::ptr::write_volatile(&mut self.h0, 0);
            core::ptr::write_volatile(&mut self.h1, 0);
            core::ptr::write_volatile(&mut self.h2, 0);
            core::ptr::write_volatile(&mut self.h3, 0);
            core::ptr::write_volatile(&mut self.h4, 0);
            core::ptr::write_volatile(&mut self.r0, 0);
            core::ptr::write_volatile(&mut self.r1, 0);
            core::ptr::write_volatile(&mut self.r2, 0);
            core::ptr::write_volatile(&mut self.r3, 0);
            core::ptr::write_volatile(&mut self.r4, 0);
            core::ptr::write_volatile(&mut self.s1, 0);
            core::ptr::write_volatile(&mut self.s2, 0);
            core::ptr::write_volatile(&mut self.s3, 0);
            core::ptr::write_volatile(&mut self.s4, 0);
        }
        secure_zero_bytes(&mut self.s);
    }
}

/// Compute Poly1305 MAC
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut poly = Poly1305::new(key);
    poly.update(msg);
    poly.finalize()
}

// ============================================================================
// CHACHA20-POLY1305 AEAD
// ============================================================================

/// Encrypt plaintext using ChaCha20-Poly1305 AEAD
///
/// Returns ciphertext || 16-byte tag.
///
/// # Arguments
/// * `key` - 256-bit encryption key
/// * `nonce` - 96-bit nonce (MUST be unique for each encryption with the same key)
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
/// * `plaintext` - Data to encrypt
///
/// # Security
/// Never reuse a nonce with the same key. Doing so completely breaks security.
pub fn aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    // Generate one-time Poly1305 key from ChaCha20 block 0
    let mut block0 = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Encrypt plaintext with ChaCha20 starting at counter 1
    let mut ciphertext = plaintext.to_vec();
    chacha20_xor(key, nonce, 1, &mut ciphertext);

    // Compute authentication tag
    let tag = compute_tag(&otk, aad, &ciphertext);

    // Zeroize sensitive data
    secure_zero_bytes(&mut otk);
    secure_zero_bytes(&mut block0);

    // Return ciphertext || tag
    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    Ok(result)
}

/// Decrypt ciphertext using ChaCha20-Poly1305 AEAD
///
/// # Arguments
/// * `key` - 256-bit encryption key
/// * `nonce` - 96-bit nonce (same as used for encryption)
/// * `aad` - Additional authenticated data (same as used for encryption)
/// * `ciphertext_and_tag` - Ciphertext || 16-byte tag
///
/// # Returns
/// * `Ok(plaintext)` if authentication succeeds
/// * `Err("tag mismatch")` if authentication fails
pub fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if ciphertext_and_tag.len() < TAG_SIZE {
        return Err("ciphertext too short");
    }

    let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
    let (ciphertext, tag) = ciphertext_and_tag.split_at(ct_len);

    // Generate one-time Poly1305 key
    let mut block0 = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Compute expected tag
    let expected_tag = compute_tag(&otk, aad, ciphertext);

    // Constant-time tag comparison
    let tag_ok = ct_eq(&expected_tag, tag);

    // Zeroize sensitive data BEFORE branching
    secure_zero_bytes(&mut otk);
    secure_zero_bytes(&mut block0);

    if !tag_ok {
        return Err("tag mismatch");
    }

    // Decrypt ciphertext
    let mut plaintext = ciphertext.to_vec();
    chacha20_xor(key, nonce, 1, &mut plaintext);

    Ok(plaintext)
}

/// Compute the AEAD authentication tag
///
/// Format: AAD || pad(AAD) || CT || pad(CT) || len(AAD) || len(CT)
fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut poly = Poly1305::new(otk);

    // AAD
    poly.update(aad);

    // Pad AAD to 16-byte boundary
    let aad_padding = (16 - (aad.len() % 16)) % 16;
    if aad_padding > 0 {
        let zeros = [0u8; 16];
        poly.update(&zeros[..aad_padding]);
    }

    // Ciphertext
    poly.update(ciphertext);

    // Pad ciphertext to 16-byte boundary
    let ct_padding = (16 - (ciphertext.len() % 16)) % 16;
    if ct_padding > 0 {
        let zeros = [0u8; 16];
        poly.update(&zeros[..ct_padding]);
    }

    // Lengths (8 bytes each, little-endian)
    let mut lengths = [0u8; 16];
    lengths[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly.update(&lengths);

    poly.finalize()
}

/// Encrypt plaintext in-place using ChaCha20-Poly1305 AEAD
///
/// The buffer must have space for TAG_SIZE additional bytes at the end.
/// Returns the total length (ciphertext + tag).
pub fn aead_encrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    plaintext_len: usize,
) -> Result<usize, &'static str> {
    if buffer.len() < plaintext_len + TAG_SIZE {
        return Err("buffer too small");
    }

    // Generate one-time Poly1305 key
    let mut block0 = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Encrypt in-place
    chacha20_xor(key, nonce, 1, &mut buffer[..plaintext_len]);

    // Compute tag
    let tag = compute_tag(&otk, aad, &buffer[..plaintext_len]);

    // Append tag
    buffer[plaintext_len..plaintext_len + TAG_SIZE].copy_from_slice(&tag);

    // Zeroize
    secure_zero_bytes(&mut otk);
    secure_zero_bytes(&mut block0);

    Ok(plaintext_len + TAG_SIZE)
}

/// Decrypt ciphertext in-place using ChaCha20-Poly1305 AEAD
///
/// Returns the plaintext length on success.
pub fn aead_decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut [u8],
    ciphertext_and_tag_len: usize,
) -> Result<usize, &'static str> {
    if ciphertext_and_tag_len < TAG_SIZE || buffer.len() < ciphertext_and_tag_len {
        return Err("invalid length");
    }

    let ct_len = ciphertext_and_tag_len - TAG_SIZE;
    let tag = &buffer[ct_len..ciphertext_and_tag_len].to_vec();

    // Generate one-time Poly1305 key
    let mut block0 = [0u8; 64];
    chacha20_block(key, nonce, 0, &mut block0);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Verify tag
    let expected_tag = compute_tag(&otk, aad, &buffer[..ct_len]);
    let tag_ok = ct_eq(&expected_tag, tag);

    // Zeroize before branching
    secure_zero_bytes(&mut otk);
    secure_zero_bytes(&mut block0);

    if !tag_ok {
        return Err("tag mismatch");
    }

    // Decrypt in-place
    chacha20_xor(key, nonce, 1, &mut buffer[..ct_len]);

    Ok(ct_len)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // RFC 8439 Test Vectors
    // ========================================================================

    /// RFC 8439 Section 2.3.2 - ChaCha20 Block Function
    #[test]
    fn test_chacha20_block_rfc8439() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
            0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1u32;

        let mut output = [0u8; 64];
        chacha20_block(&key, &nonce, counter, &mut output);

        let expected = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(output, expected);
    }

    /// Test ChaCha20 block 0 for AEAD test vector (verifies OTK generation)
    #[test]
    fn test_chacha20_block0_aead() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ];

        let mut block0 = [0u8; 64];
        chacha20_block(&key, &nonce, 0, &mut block0);

        // Expected OTK (first 32 bytes of block 0) from reference chacha20 crate
        let expected_otk = [
            0x7b, 0xac, 0x2b, 0x25, 0x2d, 0xb4, 0x47, 0xaf,
            0x09, 0xb6, 0x7a, 0x55, 0xa4, 0xe9, 0x55, 0x84,
            0x0a, 0xe1, 0xd6, 0x73, 0x10, 0x75, 0xd9, 0xeb,
            0x2a, 0x93, 0x75, 0x78, 0x3e, 0xd5, 0x53, 0xff,
        ];

        assert_eq!(&block0[..32], &expected_otk[..], "OTK mismatch");
    }

    /// Test Poly1305 tag computation with exact AEAD data
    #[test]
    fn test_poly1305_aead_tag() {
        // The OTK from block 0
        let otk = [
            0x7b, 0xac, 0x2b, 0x25, 0x2d, 0xb4, 0x47, 0xaf,
            0x09, 0xb6, 0x7a, 0x55, 0xa4, 0xe9, 0x55, 0x84,
            0x0a, 0xe1, 0xd6, 0x73, 0x10, 0x75, 0xd9, 0xeb,
            0x2a, 0x93, 0x75, 0x78, 0x3e, 0xd5, 0x53, 0xff,
        ];

        // AAD from the test
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];

        // Expected ciphertext from RFC 8439
        let ciphertext = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
            0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
            0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
            0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
            0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        let tag = compute_tag(&otk, &aad, &ciphertext);

        let expected_tag = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
        ];

        assert_eq!(tag, expected_tag, "AEAD tag mismatch");
    }

    /// RFC 8439 Section 2.5.2 - Poly1305 MAC
    #[test]
    fn test_poly1305_rfc8439() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";

        let tag = poly1305_mac(msg, &key);

        let expected = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    /// RFC 8439 Section 2.8.2 - AEAD Encryption
    #[test]
    fn test_aead_rfc8439() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";

        // Expected ciphertext (from RFC 8439 Section 2.8.2)
        let expected_ciphertext = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
            0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
            0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
            0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
            0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
            0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
            0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
            0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
            0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
            0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
            0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
            0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
            0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        // Expected tag
        let expected_tag = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
        ];

        // Encrypt
        let result = aead_encrypt(&key, &nonce, &aad, plaintext).unwrap();

        // Verify ciphertext
        assert_eq!(
            &result[..expected_ciphertext.len()],
            &expected_ciphertext[..],
            "Ciphertext mismatch"
        );

        // Verify tag
        assert_eq!(
            &result[expected_ciphertext.len()..],
            &expected_tag[..],
            "Tag mismatch"
        );

        // Decrypt and verify
        let decrypted = aead_decrypt(&key, &nonce, &aad, &result).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test tag tampering detection
    #[test]
    fn test_tag_tampering() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"secret data";

        let mut ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();

        // Tamper with the tag
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;

        // Decryption should fail
        assert!(aead_decrypt(&key, &nonce, aad, &ciphertext).is_err());
    }

    /// Test ciphertext tampering detection
    #[test]
    fn test_ciphertext_tampering() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"secret data";

        let mut ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0x01;

        // Decryption should fail
        assert!(aead_decrypt(&key, &nonce, aad, &ciphertext).is_err());
    }

    /// Test AAD tampering detection
    #[test]
    fn test_aad_tampering() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"secret data";

        let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();

        // Try to decrypt with different AAD
        let wrong_aad = b"Header";
        assert!(aead_decrypt(&key, &nonce, wrong_aad, &ciphertext).is_err());
    }

    /// Test empty plaintext
    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"";

        let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), TAG_SIZE); // Only tag, no ciphertext

        let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test empty AAD
    #[test]
    fn test_empty_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"";
        let plaintext = b"secret data";

        let ciphertext = aead_encrypt(&key, &nonce, aad, plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test in-place encryption/decryption
    #[test]
    fn test_in_place() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";
        let plaintext = b"secret data for in-place test";

        // Encrypt in-place
        let mut buffer = [0u8; 256];
        buffer[..plaintext.len()].copy_from_slice(plaintext);
        let ct_len = aead_encrypt_in_place(&key, &nonce, aad, &mut buffer, plaintext.len()).unwrap();

        // Decrypt in-place
        let pt_len = aead_decrypt_in_place(&key, &nonce, aad, &mut buffer, ct_len).unwrap();

        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buffer[..pt_len], plaintext);
    }

    /// Test large plaintext (multiple blocks)
    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let aad = b"header";

        // 1000 bytes of plaintext (multiple ChaCha20 blocks)
        let plaintext: Vec<u8> = (0..1000).map(|i| i as u8).collect();

        let ciphertext = aead_encrypt(&key, &nonce, aad, &plaintext).unwrap();
        let decrypted = aead_decrypt(&key, &nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Additional Poly1305 test - verify key clamping
    #[test]
    fn test_poly1305_clamping() {
        // Test that r is properly clamped
        let key = [0xff; 32];
        let tag = poly1305_mac(b"test", &key);

        // The tag should be deterministic with clamped r
        // (not checking exact value, just that it doesn't panic and is consistent)
        let tag2 = poly1305_mac(b"test", &key);
        assert_eq!(tag, tag2);
    }
}
