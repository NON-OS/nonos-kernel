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
//! BLAKE3 Cryptographic Hash Function
//!
//! # Features
//!
//! - **Incremental hashing**: Stream data of any size
//! - **One-shot hashing**: Simple API for complete messages
//! - **Keyed hashing**: MAC mode with 256-bit key
//! - **Key derivation**: KDF mode with context string
//! - **Extendable output (XOF)**: Generate arbitrary-length output
//! - **Verified**: Passes all official BLAKE3 test vectors
//!
//! # Performance
//!
//! This is a portable software implementation. BLAKE3 achieves its full
//! speed through SIMD parallelism; this implementation prioritizes
//! correctness and portability over raw performance.
//!
//! # Security
//!
//! - 256-bit security level
//! - Resistant to length extension attacks
//! - Secure as a MAC, PRF, and KDF

#![allow(clippy::many_single_char_names)]
#![allow(clippy::identity_op)]

extern crate alloc;

use alloc::vec::Vec;
use crate::crypto::constant_time::{secure_zero, compiler_fence};

// ============================================================================
// CONSTANTS
// ============================================================================

/// BLAKE3 initialization vector (same as BLAKE2s, first 8 words of π)
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Block size in bytes (64 bytes = 512 bits)
const BLOCK_LEN: usize = 64;

/// Chunk size in bytes (1024 bytes = 16 blocks)
const CHUNK_LEN: usize = 1024;

/// Default output length in bytes
pub const OUT_LEN: usize = 32;

/// Key length for keyed hashing
pub const KEY_LEN: usize = 32;

/// Number of rounds per compression
const ROUNDS: usize = 7;

/// Maximum tree depth (log2 of max message size)
const MAX_DEPTH: usize = 54;

// Domain separation flags
const CHUNK_START: u8         = 1 << 0;
const CHUNK_END: u8           = 1 << 1;
const PARENT: u8              = 1 << 2;
const ROOT: u8                = 1 << 3;
const KEYED_HASH: u8          = 1 << 4;
const DERIVE_KEY_CONTEXT: u8  = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

/// Message word permutation schedule (applied each round)
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

// ============================================================================
// COMPRESSION FUNCTION
// ============================================================================

/// Quarter-round mixing function G
#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One round of BLAKE3 compression
#[inline(always)]
fn round(state: &mut [u32; 16], m: &[u32; 16], schedule: &[usize; 16]) {
    // Column step
    g(state, 0, 4,  8, 12, m[schedule[0]],  m[schedule[1]]);
    g(state, 1, 5,  9, 13, m[schedule[2]],  m[schedule[3]]);
    g(state, 2, 6, 10, 14, m[schedule[4]],  m[schedule[5]]);
    g(state, 3, 7, 11, 15, m[schedule[6]],  m[schedule[7]]);
    // Diagonal step
    g(state, 0, 5, 10, 15, m[schedule[8]],  m[schedule[9]]);
    g(state, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]]);
    g(state, 2, 7,  8, 13, m[schedule[12]], m[schedule[13]]);
    g(state, 3, 4,  9, 14, m[schedule[14]], m[schedule[15]]);
}

/// BLAKE3 compression function
///
/// Compresses a 64-byte block with the given chaining value, counter, block length, and flags.
/// Returns the full 16-word state (first 8 words are the new CV, last 8 for XOF).
#[inline]
fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u8,
) -> [u32; 16] {
    let mut state = [
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags as u32,
    ];

    for r in 0..ROUNDS {
        round(&mut state, block, &MSG_SCHEDULE[r]);
    }

    // XOR the two halves
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }

    state
}

/// Convert first 8 words of state to chaining value
#[inline]
fn first_8_words(state: &[u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&state[..8]);
    cv
}

/// Parse a block into 16 little-endian u32 words
#[inline]
fn words_from_le_bytes(bytes: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

/// Convert 8 words to 32 bytes
#[inline]
fn words_to_le_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    bytes
}

// ============================================================================
// OUTPUT READER (XOF)
// ============================================================================

/// Extendable output reader for BLAKE3
///
/// Allows reading an arbitrary number of output bytes from a finalized hash.
/// Implements the BLAKE3 XOF (extendable output function) mode.
pub struct OutputReader {
    cv: [u32; 8],
    block: [u32; 16],
    block_len: u8,
    flags: u8,
    counter: u64,
    buffer: [u8; BLOCK_LEN],
    buffer_offset: usize,
}

impl OutputReader {
    fn new(cv: [u32; 8], block: [u32; 16], block_len: u8, flags: u8) -> Self {
        Self {
            cv,
            block,
            block_len,
            flags: flags | ROOT,
            counter: 0,
            buffer: [0u8; BLOCK_LEN],
            buffer_offset: BLOCK_LEN, // Force first fill
        }
    }

    /// Fill a buffer with output bytes
    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut offset = 0;

        while offset < buf.len() {
            // If buffer is exhausted, generate more
            if self.buffer_offset >= BLOCK_LEN {
                let state = compress(
                    &self.cv,
                    &self.block,
                    self.counter,
                    self.block_len as u32,
                    self.flags,
                );
                // Output all 64 bytes of the state
                for (i, &w) in state.iter().enumerate() {
                    self.buffer[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
                }
                self.counter += 1;
                self.buffer_offset = 0;
            }

            let available = BLOCK_LEN - self.buffer_offset;
            let to_copy = core::cmp::min(available, buf.len() - offset);
            buf[offset..offset + to_copy]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + to_copy]);
            self.buffer_offset += to_copy;
            offset += to_copy;
        }
    }

    /// Read exactly 32 bytes (standard hash output)
    pub fn finalize_32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }
}

impl Drop for OutputReader {
    fn drop(&mut self) {
        // Zero all sensitive state
        for w in &mut self.cv {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        for w in &mut self.block {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        secure_zero(&mut self.buffer);
        compiler_fence();
    }
}

// ============================================================================
// CHUNK STATE
// ============================================================================

/// State for processing a single chunk (1024 bytes)
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u8,
}

impl ChunkState {
    fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u8) -> Self {
        Self {
            cv: *key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        (self.blocks_compressed as usize) * BLOCK_LEN + (self.block_len as usize)
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, input: &[u8]) {
        let mut offset = 0;

        while offset < input.len() {
            // If the block is full, compress it
            if self.block_len == BLOCK_LEN as u8 {
                let block_words = words_from_le_bytes(&self.block);
                let state = compress(
                    &self.cv,
                    &block_words,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                );
                self.cv = first_8_words(&state);
                self.blocks_compressed += 1;
                self.block = [0u8; BLOCK_LEN];
                self.block_len = 0;
            }

            // Copy input to block
            let available = BLOCK_LEN - self.block_len as usize;
            let to_copy = core::cmp::min(available, input.len() - offset);
            self.block[self.block_len as usize..self.block_len as usize + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.block_len += to_copy as u8;
            offset += to_copy;
        }
    }

    fn output(&self) -> Output {
        let mut block_words = [0u32; 16];
        // Pad block with zeros if needed (already zero-initialized)
        let mut padded_block = self.block;
        let words = words_from_le_bytes(&padded_block);
        block_words = words;

        Output {
            cv: self.cv,
            block: block_words,
            block_len: self.block_len,
            counter: self.chunk_counter,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

impl Drop for ChunkState {
    fn drop(&mut self) {
        // Zero cv (contains key-derived data in keyed mode)
        for w in &mut self.cv {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        secure_zero(&mut self.block);
        compiler_fence();
    }
}

// ============================================================================
// OUTPUT NODE
// ============================================================================

/// Output of a chunk or parent node compression
#[derive(Clone, Copy)]
struct Output {
    cv: [u32; 8],
    block: [u32; 16],
    block_len: u8,
    counter: u64,
    flags: u8,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        let state = compress(&self.cv, &self.block, self.counter, self.block_len as u32, self.flags);
        first_8_words(&state)
    }

    fn root_output_bytes(&self, out: &mut [u8]) {
        let mut reader = OutputReader::new(self.cv, self.block, self.block_len, self.flags);
        reader.fill(out);
    }

    fn root_hash(&self) -> [u8; OUT_LEN] {
        let mut out = [0u8; OUT_LEN];
        self.root_output_bytes(&mut out);
        out
    }
}

/// Create a parent output from two child chaining values
fn parent_output(left_cv: [u32; 8], right_cv: [u32; 8], key_words: &[u32; 8], flags: u8) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left_cv);
    block[8..].copy_from_slice(&right_cv);
    Output {
        cv: *key_words,
        block,
        block_len: BLOCK_LEN as u8,
        counter: 0,
        flags: flags | PARENT,
    }
}

// ============================================================================
// HASHER
// ============================================================================

/// Incremental BLAKE3 hasher
///
/// Supports streaming input, keyed hashing, and key derivation.
pub struct Hasher {
    key_words: [u32; 8],
    chunk_state: ChunkState,
    cv_stack: [[u32; 8]; MAX_DEPTH],
    cv_stack_len: usize,
    flags: u8,
}

impl Hasher {
    /// Create a new hasher for unkeyed hashing
    pub fn new() -> Self {
        Self::new_internal(&IV, 0)
    }

    /// Create a new hasher for keyed hashing (MAC mode)
    ///
    /// The key must be exactly 32 bytes.
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let key_words = key_words_from_bytes(key);
        Self::new_internal(&key_words, KEYED_HASH)
    }

    /// Create a new hasher for key derivation (KDF mode)
    ///
    /// The context string should be unique to your application and use case.
    /// Example: "NØNOS v1.0 file encryption key"
    pub fn new_derive_key(context: &str) -> Self {
        // Hash the context string with DERIVE_KEY_CONTEXT
        let context_hasher = Self::new_internal(&IV, DERIVE_KEY_CONTEXT);
        let mut context_hasher = context_hasher;
        context_hasher.update(context.as_bytes());
        let context_key = context_hasher.finalize();
        let context_key_words = key_words_from_bytes(&context_key);

        Self::new_internal(&context_key_words, DERIVE_KEY_MATERIAL)
    }

    fn new_internal(key_words: &[u32; 8], flags: u8) -> Self {
        Self {
            key_words: *key_words,
            chunk_state: ChunkState::new(key_words, 0, flags),
            cv_stack: [[0u32; 8]; MAX_DEPTH],
            cv_stack_len: 0,
            flags,
        }
    }

    fn push_cv(&mut self, cv: [u32; 8], chunk_counter: u64) {
        // Merge CVs when we have complete subtrees
        // A subtree at position i is complete when bit i of chunk_counter is 0
        let mut cv = cv;
        let mut total_chunks = chunk_counter;

        while total_chunks & 1 == 1 {
            debug_assert!(self.cv_stack_len > 0);
            self.cv_stack_len -= 1;
            let left = self.cv_stack[self.cv_stack_len];
            cv = parent_output(left, cv, &self.key_words, self.flags).chaining_value();
            total_chunks >>= 1;
        }

        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    /// Update the hasher with input bytes
    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        let mut offset = 0;

        while offset < input.len() {
            // If the current chunk is full, finalize it and start a new one
            if self.chunk_state.len() == CHUNK_LEN {
                let cv = self.chunk_state.output().chaining_value();
                let chunk_counter = self.chunk_state.chunk_counter;
                self.push_cv(cv, chunk_counter);
                self.chunk_state = ChunkState::new(
                    &self.key_words,
                    chunk_counter + 1,
                    self.flags,
                );
            }

            // Determine how much to process in this iteration
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = core::cmp::min(want, input.len() - offset);
            self.chunk_state.update(&input[offset..offset + take]);
            offset += take;
        }

        self
    }

    fn final_output(&self) -> Output {
        // Get the output of the current (possibly partial) chunk
        let mut output = self.chunk_state.output();

        // If there are CVs on the stack, combine them
        let mut parent_nodes_remaining = self.cv_stack_len;
        while parent_nodes_remaining > 0 {
            parent_nodes_remaining -= 1;
            let left = self.cv_stack[parent_nodes_remaining];
            output = parent_output(left, output.chaining_value(), &self.key_words, self.flags);
        }

        output
    }

    /// Finalize and return the 32-byte hash
    pub fn finalize(&self) -> [u8; OUT_LEN] {
        self.final_output().root_hash()
    }

    /// Finalize and return an extendable output reader
    pub fn finalize_xof(&self) -> OutputReader {
        let output = self.final_output();
        OutputReader::new(output.cv, output.block, output.block_len, output.flags)
    }

    /// Reset the hasher for reuse with the same key/context
    pub fn reset(&mut self) {
        self.chunk_state = ChunkState::new(&self.key_words, 0, self.flags);
        self.cv_stack_len = 0;
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        // Zero key words (CRITICAL for keyed hashing mode!)
        for w in &mut self.key_words {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        // Zero CV stack
        for cv in &mut self.cv_stack {
            for w in cv {
                unsafe { core::ptr::write_volatile(w, 0); }
            }
        }
        compiler_fence();
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn key_words_from_bytes(key: &[u8; KEY_LEN]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        words[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    words
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// One-shot BLAKE3 hash (32 bytes)
///
/// This is the simplest way to hash data. For incremental hashing
/// or keyed/derived modes, use `Hasher`.
pub fn blake3_hash(input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

/// One-shot BLAKE3 hash with arbitrary output length
pub fn blake3_hash_xof(input: &[u8], output: &mut [u8]) {
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize_xof().fill(output);
}

/// One-shot keyed BLAKE3 hash (MAC)
pub fn blake3_keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> [u8; OUT_LEN] {
    let mut hasher = Hasher::new_keyed(key);
    hasher.update(input);
    hasher.finalize()
}

/// One-shot key derivation
pub fn blake3_derive_key(context: &str, key_material: &[u8], output: &mut [u8]) {
    let mut hasher = Hasher::new_derive_key(context);
    hasher.update(key_material);
    hasher.finalize_xof().fill(output);
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ========================================================================
    // Official BLAKE3 Test Vectors
    // From: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    // ========================================================================

    /// Generate test input: repeating pattern of 0..250
    fn test_input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    // Test vector: empty input
    #[test]
    fn test_empty() {
        let hash = blake3_hash(&[]);
        let expected = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
            0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
            0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
            0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 1 byte
    #[test]
    fn test_1_byte() {
        let input = test_input(1);
        let hash = blake3_hash(&input);
        let expected = [
            0x2d, 0x3a, 0xde, 0xdf, 0xf1, 0x1b, 0x61, 0xf1,
            0x4c, 0x88, 0x6e, 0x35, 0xaf, 0xa0, 0x36, 0x73,
            0x6d, 0xcd, 0x87, 0xa7, 0x4d, 0x27, 0xb5, 0xc1,
            0x51, 0x02, 0x25, 0xd0, 0xf5, 0x92, 0xe2, 0x13,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 2 bytes
    #[test]
    fn test_2_bytes() {
        let input = test_input(2);
        let hash = blake3_hash(&input);
        let expected = [
            0x7b, 0x70, 0x15, 0xbb, 0x92, 0xcf, 0x0b, 0x31,
            0x80, 0x37, 0x70, 0x2a, 0x6c, 0xdd, 0x81, 0xde,
            0xe4, 0x12, 0x24, 0xf7, 0x34, 0x68, 0x4c, 0x2c,
            0x12, 0x2c, 0xd6, 0x35, 0x9c, 0xb1, 0xee, 0x63,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 3 bytes
    #[test]
    fn test_3_bytes() {
        let input = test_input(3);
        let hash = blake3_hash(&input);
        let expected = [
            0xe1, 0xbe, 0x4d, 0x7a, 0x8a, 0xb5, 0x56, 0x0a,
            0xa4, 0x19, 0x9e, 0xea, 0x33, 0x98, 0x49, 0xba,
            0x8e, 0x29, 0x3d, 0x55, 0xca, 0x0a, 0x81, 0x00,
            0x67, 0x26, 0xd1, 0x84, 0x51, 0x9e, 0x64, 0x7f,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 1023 bytes (one byte short of a chunk)
    #[test]
    fn test_1023_bytes() {
        let input = test_input(1023);
        let hash = blake3_hash(&input);
        // Verified against reference blake3 crate v1.8
        let expected = [
            0x10, 0x10, 0x89, 0x70, 0xee, 0xda, 0x3e, 0xb9,
            0x32, 0xba, 0xac, 0x14, 0x28, 0xc7, 0xa2, 0x16,
            0x3b, 0x0e, 0x92, 0x4c, 0x9a, 0x9e, 0x25, 0xb3,
            0x5b, 0xba, 0x72, 0xb2, 0x8f, 0x70, 0xbd, 0x11,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 1024 bytes (exactly one chunk)
    #[test]
    fn test_1024_bytes() {
        let input = test_input(1024);
        let hash = blake3_hash(&input);
        // Verified against reference blake3 crate v1.8
        let expected = [
            0x42, 0x21, 0x47, 0x39, 0xf0, 0x95, 0xa4, 0x06,
            0xf3, 0xfc, 0x83, 0xde, 0xb8, 0x89, 0x74, 0x4a,
            0xc0, 0x0d, 0xf8, 0x31, 0xc1, 0x0d, 0xaa, 0x55,
            0x18, 0x9b, 0x5d, 0x12, 0x1c, 0x85, 0x5a, 0xf7,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 1025 bytes (one byte into second chunk)
    #[test]
    fn test_1025_bytes() {
        let input = test_input(1025);
        let hash = blake3_hash(&input);
        // Verified against reference blake3 crate v1.8
        let expected = [
            0xd0, 0x02, 0x78, 0xae, 0x47, 0xeb, 0x27, 0xb3,
            0x4f, 0xae, 0xcf, 0x67, 0xb4, 0xfe, 0x26, 0x3f,
            0x82, 0xd5, 0x41, 0x29, 0x16, 0xc1, 0xff, 0xd9,
            0x7c, 0x8c, 0xb7, 0xfb, 0x81, 0x4b, 0x84, 0x44,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 2048 bytes (two chunks)
    #[test]
    fn test_2048_bytes() {
        let input = test_input(2048);
        let hash = blake3_hash(&input);
        let expected = [
            0xe7, 0x76, 0xb6, 0x02, 0x8c, 0x7c, 0xd2, 0x2a,
            0x4d, 0x0b, 0xa1, 0x82, 0xa8, 0xbf, 0x62, 0x20,
            0x5d, 0x2e, 0xf5, 0x76, 0x46, 0x7e, 0x83, 0x8e,
            0xd6, 0xf2, 0x52, 0x9b, 0x85, 0xfb, 0xa2, 0x4a,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 8192 bytes (8 chunks)
    #[test]
    fn test_8192_bytes() {
        let input = test_input(8192);
        let hash = blake3_hash(&input);
        let expected = [
            0xaa, 0xe7, 0x92, 0x48, 0x4c, 0x8e, 0xfe, 0x4f,
            0x19, 0xe2, 0xca, 0x7d, 0x37, 0x1d, 0x8c, 0x46,
            0x7f, 0xfb, 0x10, 0x74, 0x8d, 0x8a, 0x5a, 0x1a,
            0xe5, 0x79, 0x94, 0x8f, 0x71, 0x8a, 0x2a, 0x63,
        ];
        assert_eq!(hash, expected);
    }

    // Test vector: 31744 bytes (to test tree structure)
    #[test]
    fn test_31744_bytes() {
        let input = test_input(31744);
        let hash = blake3_hash(&input);
        let expected = [
            0x62, 0xb6, 0x96, 0x0e, 0x1a, 0x44, 0xbc, 0xc1,
            0xeb, 0x1a, 0x61, 0x1a, 0x8d, 0x62, 0x35, 0xb6,
            0xb4, 0xb7, 0x8f, 0x32, 0xe7, 0xab, 0xc4, 0xfb,
            0x4c, 0x6c, 0xdc, 0xce, 0x94, 0x89, 0x5c, 0x47,
        ];
        assert_eq!(hash, expected);
    }

    // ========================================================================
    // Incremental Hashing Tests
    // ========================================================================

    #[test]
    fn test_incremental_single() {
        let input = test_input(1024);
        let mut hasher = Hasher::new();
        hasher.update(&input);
        let hash1 = hasher.finalize();
        let hash2 = blake3_hash(&input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_incremental_chunks() {
        let input = test_input(4096);
        let mut hasher = Hasher::new();

        // Feed in various chunk sizes
        hasher.update(&input[0..100]);
        hasher.update(&input[100..1000]);
        hasher.update(&input[1000..1024]);
        hasher.update(&input[1024..2048]);
        hasher.update(&input[2048..4096]);

        let hash1 = hasher.finalize();
        let hash2 = blake3_hash(&input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_incremental_byte_by_byte() {
        let input = test_input(256);
        let mut hasher = Hasher::new();
        for &byte in &input {
            hasher.update(&[byte]);
        }
        let hash1 = hasher.finalize();
        let hash2 = blake3_hash(&input);
        assert_eq!(hash1, hash2);
    }

    // ========================================================================
    // Keyed Hashing Tests
    // ========================================================================

    #[test]
    fn test_keyed_hash_empty() {
        // Test key: all zeros
        let key = [0u8; 32];
        let hash = blake3_keyed_hash(&key, &[]);
        // This should be different from unkeyed hash of empty
        let unkeyed = blake3_hash(&[]);
        assert_ne!(hash, unkeyed);
    }

    #[test]
    fn test_keyed_hash_official() {
        // Keyed hash test vector
        // Key: 0..31, input: test_input(1) = [0]
        // Verified against reference blake3 crate v1.8
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let input = test_input(1);
        let hash = blake3_keyed_hash(&key, &input);
        let expected = [
            0xd0, 0x8b, 0x45, 0xc6, 0xb1, 0x27, 0xee, 0x94,
            0xf3, 0xf8, 0x52, 0x7a, 0x0b, 0x82, 0xa5, 0xf8,
            0x0b, 0xe1, 0x69, 0x5a, 0x0e, 0xae, 0xc6, 0x02,
            0x2e, 0x77, 0x2c, 0x0e, 0xb9, 0x5a, 0x7e, 0x8b,
        ];
        assert_eq!(hash, expected);
    }

    // ========================================================================
    // Key Derivation Tests
    // ========================================================================

    #[test]
    fn test_derive_key_official() {
        // Official test vector
        let context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
        let input = test_input(1);
        let mut output = [0u8; 32];
        blake3_derive_key(context, &input, &mut output);
        let expected = [
            0xb3, 0xe2, 0xe3, 0x40, 0xa1, 0x17, 0xa4, 0x99,
            0xc6, 0xcf, 0x23, 0x98, 0xa1, 0x9e, 0xe0, 0xd2,
            0x9c, 0xca, 0x2b, 0xb7, 0x40, 0x4c, 0x73, 0x06,
            0x33, 0x82, 0x69, 0x3b, 0xf6, 0x6c, 0xb0, 0x6c,
        ];
        assert_eq!(output, expected);
    }

    // ========================================================================
    // XOF Tests
    // ========================================================================

    #[test]
    fn test_xof_extended() {
        let input = test_input(1);
        let mut hasher = Hasher::new();
        hasher.update(&input);

        // Get 64 bytes
        let mut output = [0u8; 64];
        hasher.finalize_xof().fill(&mut output);

        // First 32 bytes should match regular hash
        let hash = blake3_hash(&input);
        assert_eq!(&output[..32], &hash);
    }

    #[test]
    fn test_xof_incremental() {
        let input = test_input(100);
        let mut hasher = Hasher::new();
        hasher.update(&input);

        let mut reader = hasher.finalize_xof();

        // Read in chunks
        let mut out1 = [0u8; 10];
        let mut out2 = [0u8; 22];
        let mut out3 = [0u8; 32];
        reader.fill(&mut out1);
        reader.fill(&mut out2);
        reader.fill(&mut out3);

        // Should match reading all at once
        let mut hasher2 = Hasher::new();
        hasher2.update(&input);
        let mut all = [0u8; 64];
        hasher2.finalize_xof().fill(&mut all);

        assert_eq!(&out1, &all[0..10]);
        assert_eq!(&out2, &all[10..32]);
        assert_eq!(&out3, &all[32..64]);
    }

    // ========================================================================
    // Reset Tests
    // ========================================================================

    #[test]
    fn test_reset() {
        let input1 = test_input(100);
        let input2 = test_input(200);

        let mut hasher = Hasher::new();
        hasher.update(&input1);
        let hash1 = hasher.finalize();

        hasher.reset();
        hasher.update(&input2);
        let hash2 = hasher.finalize();

        // hash2 should match hashing input2 directly
        assert_eq!(hash2, blake3_hash(&input2));
        // And should be different from hash1
        assert_ne!(hash1, hash2);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_chunk_boundary() {
        // Test behavior at exact chunk boundary
        let input = test_input(CHUNK_LEN);
        let hash = blake3_hash(&input);

        let mut hasher = Hasher::new();
        hasher.update(&input[..512]);
        hasher.update(&input[512..]);
        assert_eq!(hash, hasher.finalize());
    }

    #[test]
    fn test_block_boundary() {
        // Test behavior at exact block boundary
        let input = test_input(BLOCK_LEN);
        let hash = blake3_hash(&input);

        let mut hasher = Hasher::new();
        hasher.update(&input[..32]);
        hasher.update(&input[32..]);
        assert_eq!(hash, hasher.finalize());
    }

    #[test]
    fn test_large_input() {
        // Test with a relatively large input to exercise tree structure
        let input = test_input(100_000);
        let hash = blake3_hash(&input);

        // Verify incremental gives same result
        let mut hasher = Hasher::new();
        for chunk in input.chunks(1337) {
            hasher.update(chunk);
        }
        assert_eq!(hash, hasher.finalize());
    }
}
