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

use core::arch::x86_64::{__cpuid, _rdtsc};
use core::sync::atomic::Ordering;
use sha3::{Digest, Sha3_256};

use super::super::constants::*;
use super::hwrng::{has_rdrand, has_rdseed, rdrand64, rdseed64};
use super::state::ENTROPY_POOL;

pub(super) fn secure_hash(data: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub(super) fn collect_entropy() -> u64 {
    let mut entropy = ENTROPY_POOL.load(Ordering::Relaxed);

    unsafe {
        let tsc1 = _rdtsc();
        for _ in 0..ENTROPY_SPIN_ITERATIONS {
            core::hint::spin_loop();
        }
        let tsc2 = _rdtsc();
        entropy ^= tsc1.wrapping_mul(tsc2);
    }

    let cpuid0 = __cpuid(0);
    let cpuid1 = __cpuid(CPUID_FEATURES_LEAF);
    entropy ^= (cpuid0.eax as u64) << 32 | (cpuid0.ebx as u64);
    entropy ^= (cpuid1.ecx as u64) << 16 | (cpuid1.edx as u64);

    if has_rdrand() {
        if let Some(hw_rng) = rdrand64() {
            entropy ^= hw_rng;
        }
    }
    if has_rdseed() {
        if let Some(hw_rng) = rdseed64() {
            entropy ^= hw_rng;
        }
    }

    entropy = entropy.wrapping_mul(ENTROPY_MIX_MULTIPLIER);
    ENTROPY_POOL.store(entropy, Ordering::Relaxed);
    entropy
}
