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

use spin::Mutex;

pub(super) const POOL_SIZE: usize = 4096;
pub(super) const MIN_ENTROPY_BITS: u64 = 256;

pub(super) struct EntropyPoolState {
    pub pool: [u8; POOL_SIZE],
    pub write_pos: usize,
    pub entropy_bits: u64,
    pub prng_state: [u64; 4],
    pub bytes_extracted: u64,
    pub bits_added: u64,
}

impl EntropyPoolState {
    pub(super) const fn new() -> Self {
        Self {
            pool: [0u8; POOL_SIZE],
            write_pos: 0,
            entropy_bits: 0,
            prng_state: [
                0x853c49e6748fea9b,
                0xda3e39cb94b95bdb,
                0x9c30d539a1d1c26f,
                0x5b5d3cb4d7e8f3a1,
            ],
            bytes_extracted: 0,
            bits_added: 0,
        }
    }
}

pub(super) static POOL: Mutex<EntropyPoolState> = Mutex::new(EntropyPoolState::new());

pub(crate) fn add_entropy(data: &[u8], estimated_bits: u64) {
    super::mix::mix_entropy(&mut POOL.lock(), data, estimated_bits);
}

pub(crate) fn get_entropy_available() -> u64 {
    POOL.lock().entropy_bits
}

pub(crate) fn init_pool() {
    for _ in 0..8 {
        super::hardware::add_hardware_entropy();
    }
    for _ in 0..16 {
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        add_entropy(&tsc.to_le_bytes(), 4);
    }
}
