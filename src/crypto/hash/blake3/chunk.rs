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

use crate::crypto::constant_time::{secure_zero, compiler_fence};
use super::compress::{compress, first_8_words, words_from_le_bytes};
use super::output::Output;
use super::{BLOCK_LEN, CHUNK_START, CHUNK_END};

pub(crate) struct ChunkState {
    cv: [u32; 8],
    pub(crate) chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: u8,
}

impl ChunkState {
    pub(crate) fn new(key_words: &[u32; 8], chunk_counter: u64, flags: u8) -> Self {
        Self {
            cv: *key_words,
            chunk_counter,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    pub(crate) fn len(&self) -> usize {
        (self.blocks_compressed as usize) * BLOCK_LEN + (self.block_len as usize)
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) {
        let mut offset = 0;
        while offset < input.len() {
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

            let available = BLOCK_LEN - self.block_len as usize;
            let to_copy = core::cmp::min(available, input.len() - offset);
            self.block[self.block_len as usize..self.block_len as usize + to_copy]
                .copy_from_slice(&input[offset..offset + to_copy]);
            self.block_len += to_copy as u8;
            offset += to_copy;
        }
    }

    pub(crate) fn output(&self) -> Output {
        let block_words = words_from_le_bytes(&self.block);

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
        // SAFETY: Using volatile writes to prevent the compiler from optimizing
        // away the zeroing of sensitive cryptographic state.
        for w in &mut self.cv {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        secure_zero(&mut self.block);
        compiler_fence();
    }
}
