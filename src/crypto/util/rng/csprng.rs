// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

//! ChaCha20-based cryptographically secure pseudo-random number generator.

use core::ptr;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};
1 << 20; // ~1 million blocks
impl ChaChaRng {
    /// Create a new ChaChaRng with the given 256-bit seed.
    pub fn new(seed: [u8; 32]) -> Self {
        let mut s = Self {
            key: seed,
            state: [0u32; 16],
            output: [0u8; 64],
            index: 64,
            blocks_generated: 0,
        };
        s.initialize_state(&seed);
        s
    }

    /// Initialize the ChaCha20 state from a seed.
    fn initialize_state(&mut self, seed: &[u8; 32]) {
        self.key = *seed;
        self.state[0] = 0x6170_7865; // "expa"
        self.state[1] = 0x3320_646e; // "nd 3"
        self.state[2] = 0x7962_2d32; // "2-by"
        self.state[3] = 0x6b20_6574; // "te k"

        for i in 0..8 {
            let j = i * 4;
            self.state[4 + i] =
                u32::from_le_bytes([seed[j], seed[j + 1], seed[j + 2], seed[j + 3]]);
        }

        // Counter (2 words) and nonce (2 words)
        self.state[12] = 0;
        self.state[13] = 0;
        self.state[14] = 0;
        self.state[15] = 0;

        self.index = 64;
        self.blocks_generated = 0;
    }

    #[inline(always)]
    fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);

        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);

        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);

        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }

    fn generate_block(&mut self) {
        let mut working = self.state;

        // 20 rounds (10 double-rounds)
        for _ in 0..10 {
            // Column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
        }

        for (i, w) in working.iter().enumerate() {
            let bytes = w.to_le_bytes();
            let off = i * 4;
            self.output[off..off + 4].copy_from_slice(&bytes);
        }

        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }

        self.index = 0;
        self.blocks_generated += 1;
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            if self.index >= 64 {
                self.generate_block();
            }
            let take = core::cmp::min(64 - self.index, out.len() - written);
            out[written..written + take]
                .copy_from_slice(&self.output[self.index..self.index + take]);
            self.index += take;
            written += take;
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut tmp = [0u8; 8];
        self.fill_bytes(&mut tmp);
        u64::from_le_bytes(tmp)
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut tmp = [0u8; 4];
        self.fill_bytes(&mut tmp);
        u32::from_le_bytes(tmp)
    }

    pub fn reseed(&mut self, seed: [u8; 32]) {
        // # Securely erase output buffer
        for b in &mut self.output {
            unsafe { ptr::write_volatile(b, 0) };
        }
        compiler_fence();
        memory_fence();

        self.initialize_state(&seed);
    }

    pub fn needs_reseed(&self) -> bool {
        self.blocks_generated >= RESEED_INTERVAL
    }

    pub fn blocks_generated(&self) -> u64 {
        self.blocks_generated
    }
}

impl Drop for ChaChaRng {
    fn drop(&mut self) {
        //  { # Securely erase all sensitive state using volatile writes }
        for b in &mut self.key {
            unsafe { ptr::write_volatile(b, 0) };
        }
        for w in &mut self.state {
            unsafe { ptr::write_volatile(w, 0) };
        }
        for b in &mut self.output {
            unsafe { ptr::write_volatile(b, 0) };
        }
        unsafe { ptr::write_volatile(&mut self.index, 0) };
        unsafe { ptr::write_volatile(&mut self.blocks_generated, 0) };
        // Memory barriers to ensure erasure is complete and visible
        compiler_fence();
        memory_fence();
    }
}
