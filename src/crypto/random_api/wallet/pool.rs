// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

const ENTROPY_POOL_LEN: usize = 256;

pub(super) struct EntropyPool {
    bytes: [u8; ENTROPY_POOL_LEN],
    used: usize,
}

impl EntropyPool {
    pub(super) const fn new() -> Self {
        Self { bytes: [0; ENTROPY_POOL_LEN], used: 0 }
    }

    pub(super) fn push_u64(&mut self, value: u64) {
        self.append(&value.to_le_bytes());
    }

    pub(super) fn append(&mut self, input: &[u8]) {
        for (idx, byte) in input.iter().enumerate() {
            if self.used < self.bytes.len() {
                self.bytes[self.used] = *byte;
                self.used += 1;
            } else {
                self.bytes[idx % ENTROPY_POOL_LEN] ^= *byte;
            }
        }
    }

    pub(super) fn bytes(&self) -> &[u8; ENTROPY_POOL_LEN] {
        &self.bytes
    }

    pub(super) fn bytes_mut(&mut self) -> &mut [u8; ENTROPY_POOL_LEN] {
        &mut self.bytes
    }

    pub(super) fn zeroize(&mut self) {
        for byte in self.bytes.iter_mut() {
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
