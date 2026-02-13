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

mod collector;
mod getrandom;
mod sources;
mod types;
mod util;

pub use types::{
    DS_ENTROPY_ACCUM, DS_ENTROPY_OUTPUT, ENTROPY_POOL_SIZE, HW_RNG_ITERATIONS, TSC_JITTER_ROUNDS,
};

pub use collector::{
    collect_boot_entropy, collect_boot_entropy_64_with_st, get_rtc_timestamp_with_st, seed_entropy,
};

// Re-export
pub fn collect_boot_entropy_64(st: &uefi::prelude::SystemTable<uefi::prelude::Boot>) -> Result<[u8; 64], &'static str> {
    collect_boot_entropy_64_with_st(st)
}

/// Collect entropy without needing the SystemTable.
pub fn collect_entropy_no_st() -> Result<[u8; 64], &'static str> {
    use types::{DS_ENTROPY_ACCUM, DS_ENTROPY_OUTPUT, HW_RNG_ITERATIONS, TSC_JITTER_ROUNDS};
    use sources::{collect_hw_rng_bytes, rdtsc_serialized};
    use util::is_weak_entropy;

    let mut h = blake3::Hasher::new_derive_key(DS_ENTROPY_ACCUM);
    let mut hw = [0u8; 64];
    collect_hw_rng_bytes(&mut hw, HW_RNG_ITERATIONS);
    h.update(&hw);
    for round in 0u32..TSC_JITTER_ROUNDS as u32 {
        let t1 = rdtsc_serialized();
        for _ in 0..100 { core::hint::spin_loop(); }
        let t2 = rdtsc_serialized();
        let delta = t2.wrapping_sub(t1);

        let mut frame = [0u8; 24];
        frame[0..8].copy_from_slice(&t1.to_le_bytes());
        frame[8..16].copy_from_slice(&t2.to_le_bytes());
        frame[16..20].copy_from_slice(&round.to_le_bytes());
        frame[20..24].copy_from_slice(&(delta.rotate_left((round % 63) + 1)).to_le_bytes()[0..4]);
        h.update(&frame);
    }

    let mut out = [0u8; 64];
    blake3::Hasher::new_derive_key(DS_ENTROPY_OUTPUT)
        .update(h.finalize().as_bytes())
        .finalize_xof()
        .fill(&mut out);

    if is_weak_entropy(&out) {
        return Err("Entropy collection failed: insufficient randomness");
    }

    Ok(out)
}

pub fn get_rtc_timestamp() -> [u8; 8] {
    rdtsc_serialized().to_le_bytes()
}

pub use getrandom::getrandom;
pub use sources::{rdrand64, rdseed64, rdtsc_serialized};
pub use util::{is_weak_entropy, scrub};
