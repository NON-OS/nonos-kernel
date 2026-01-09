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
use super::compress::{compress, first_8_words};
use super::{BLOCK_LEN, OUT_LEN, ROOT, PARENT};

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
    pub(crate) fn new(cv: [u32; 8], block: [u32; 16], block_len: u8, flags: u8) -> Self {
        Self {
            cv,
            block,
            block_len,
            flags: flags | ROOT,
            counter: 0,
            buffer: [0u8; BLOCK_LEN],
            buffer_offset: BLOCK_LEN,
        }
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut offset = 0;

        while offset < buf.len() {
            if self.buffer_offset >= BLOCK_LEN {
                let state = compress(
                    &self.cv,
                    &self.block,
                    self.counter,
                    self.block_len as u32,
                    self.flags,
                );
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

    pub fn finalize_32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }
}

impl Drop for OutputReader {
    fn drop(&mut self) {
        // SAFETY: Using volatile writes to prevent the compiler from optimizing
        // away the zeroing of sensitive cryptographic state.
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

// SECURITY: No Copy trait - output contains sensitive state that must be zeroized
#[derive(Clone)]
pub(crate) struct Output {
    pub(crate) cv: [u32; 8],
    pub(crate) block: [u32; 16],
    pub(crate) block_len: u8,
    pub(crate) counter: u64,
    pub(crate) flags: u8,
}

impl Drop for Output {
    fn drop(&mut self) {
        // SAFETY: Using volatile writes to prevent the compiler from optimizing
        // away the zeroing of sensitive cryptographic state.
        for w in &mut self.cv {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        for w in &mut self.block {
            unsafe { core::ptr::write_volatile(w, 0); }
        }
        compiler_fence();
    }
}

impl Output {
    pub(crate) fn chaining_value(&self) -> [u32; 8] {
        let state = compress(&self.cv, &self.block, self.counter, self.block_len as u32, self.flags);
        first_8_words(&state)
    }

    pub(crate) fn root_output_bytes(&self, out: &mut [u8]) {
        let mut reader = OutputReader::new(self.cv, self.block, self.block_len, self.flags);
        reader.fill(out);
    }

    pub(crate) fn root_hash(&self) -> [u8; OUT_LEN] {
        let mut out = [0u8; OUT_LEN];
        self.root_output_bytes(&mut out);
        out
    }
}

pub(crate) fn parent_output(left_cv: [u32; 8], right_cv: [u32; 8], key_words: &[u32; 8], flags: u8) -> Output {
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
