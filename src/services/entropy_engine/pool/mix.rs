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

use super::state::{EntropyPoolState, POOL_SIZE};

pub(super) fn mix_entropy(pool: &mut EntropyPoolState, data: &[u8], estimated_bits: u64) {
    for &byte in data {
        pool.pool[pool.write_pos] ^= byte;
        let left = (pool.write_pos + POOL_SIZE - 1) % POOL_SIZE;
        let right = (pool.write_pos + 1) % POOL_SIZE;
        pool.pool[left] = pool.pool[left].rotate_left(3) ^ byte;
        pool.pool[right] = pool.pool[right].rotate_right(5) ^ byte;
        pool.write_pos = (pool.write_pos + 1) % POOL_SIZE;
    }
    pool.entropy_bits =
        core::cmp::min(pool.entropy_bits.saturating_add(estimated_bits), (POOL_SIZE * 8) as u64);
    pool.bits_added += estimated_bits;
}

pub(super) fn reseed_prng(pool: &mut EntropyPoolState) {
    for i in 0..4 {
        let start = (i * POOL_SIZE / 4) % POOL_SIZE;
        let mut val: u64 = 0;
        for j in 0..8 {
            val |= (pool.pool[(start + j) % POOL_SIZE] as u64) << (j * 8);
        }
        pool.prng_state[i] ^= val;
    }
}

pub(super) fn xoshiro_next(pool: &mut EntropyPoolState) -> u64 {
    let result = pool.prng_state[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
    let t = pool.prng_state[1] << 17;
    pool.prng_state[2] ^= pool.prng_state[0];
    pool.prng_state[3] ^= pool.prng_state[1];
    pool.prng_state[1] ^= pool.prng_state[2];
    pool.prng_state[0] ^= pool.prng_state[3];
    pool.prng_state[2] ^= t;
    pool.prng_state[3] = pool.prng_state[3].rotate_left(45);
    result
}
