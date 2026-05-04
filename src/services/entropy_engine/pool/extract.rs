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

use super::mix::{reseed_prng, xoshiro_next};
use super::state::{MIN_ENTROPY_BITS, POOL};

pub(crate) fn get_random_bytes(output: &mut [u8]) -> bool {
    let mut pool = POOL.lock();
    if pool.entropy_bits < MIN_ENTROPY_BITS {
        return false;
    }
    reseed_prng(&mut pool);
    for chunk in output.chunks_mut(8) {
        let random = xoshiro_next(&mut pool);
        let bytes = random.to_le_bytes();
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = bytes[i];
        }
    }
    let bits_used = (output.len() * 8) as u64;
    pool.entropy_bits = pool.entropy_bits.saturating_sub(bits_used);
    pool.bytes_extracted += output.len() as u64;
    true
}

pub(crate) fn get_random_bytes_blocking(output: &mut [u8]) {
    loop {
        if get_random_bytes(output) {
            return;
        }
        super::hardware::add_hardware_entropy();
        crate::sched::yield_now();
    }
}
