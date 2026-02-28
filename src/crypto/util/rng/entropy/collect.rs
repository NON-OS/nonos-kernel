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

use core::sync::atomic::Ordering;
use super::error::EntropyError;
use super::state::{ENTROPY_COUNTER, HARDWARE_ENTROPY_VERIFIED, BOOTLOADER_ENTROPY_PROVIDED};
use super::hardware::{has_rdrand, has_rdseed, try_rdrand64, try_rdseed64, read_tsc};

pub fn init_entropy() -> Result<(), EntropyError> {
    if has_rdrand() || has_rdseed() {
        HARDWARE_ENTROPY_VERIFIED.store(true, Ordering::SeqCst);
        return Ok(());
    }

    if BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::SeqCst) {
        return Ok(());
    }

    Err(EntropyError::NoHardwareSource)
}

pub fn mark_bootloader_entropy_provided() {
    BOOTLOADER_ENTROPY_PROVIDED.store(true, Ordering::SeqCst);
}

#[inline]
pub fn has_adequate_entropy() -> bool {
    has_rdrand() || has_rdseed() || BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::Acquire)
}

pub fn verify_entropy_sources() -> Result<(), EntropyError> {
    if has_rdrand() || has_rdseed() {
        return Ok(());
    }

    if BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::Acquire) {
        return Ok(());
    }

    Err(EntropyError::NoHardwareSource)
}

pub fn get_entropy64_secure() -> Result<u64, EntropyError> {
    if let Some(v) = try_rdseed64() {
        return Ok(v);
    }

    if let Some(v) = try_rdrand64() {
        return Ok(v);
    }

    Err(EntropyError::HardwareFailure)
}

pub fn get_entropy64() -> u64 {
    if let Ok(v) = get_entropy64_secure() {
        return v;
    }

    emergency_entropy_mix()
}

#[cold]
fn emergency_entropy_mix() -> u64 {
    let counter = ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst);
    let tsc = read_tsc();

    let mut state = counter;
    state = state.wrapping_add(0x9e3779b97f4a7c15);
    state ^= tsc;
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    state = (state ^ (state >> 27)).wrapping_mul(0x94d049bb133111eb);
    state ^= state >> 31;

    state
}

pub fn get_tsc_entropy() -> u64 {
    let counter = ENTROPY_COUNTER.fetch_add(1, Ordering::SeqCst);
    let tsc = read_tsc();
    counter ^ tsc
}

pub fn collect_seed_entropy_secure() -> Result<[u8; 32], EntropyError> {
    let mut seed = [0u8; 32];
    let mut offset = 0;
    let mut secure_bytes = 0usize;

    while offset < 32 {
        if let Some(v) = try_rdseed64() {
            let remaining = 32 - offset;
            let copy_len = core::cmp::min(8, remaining);
            seed[offset..offset + copy_len].copy_from_slice(&v.to_le_bytes()[..copy_len]);
            offset += copy_len;
            secure_bytes += copy_len;
        } else {
            break;
        }
    }

    while offset < 32 {
        if let Some(v) = try_rdrand64() {
            let remaining = 32 - offset;
            let copy_len = core::cmp::min(8, remaining);
            seed[offset..offset + copy_len].copy_from_slice(&v.to_le_bytes()[..copy_len]);
            offset += copy_len;
            secure_bytes += copy_len;
        } else {
            break;
        }
    }

    if secure_bytes < 32 {
        for b in &mut seed {
            *b = 0;
        }
        return Err(EntropyError::InsufficientEntropy);
    }

    Ok(seed)
}

pub fn collect_seed_entropy() -> [u8; 32] {
    if let Ok(seed) = collect_seed_entropy_secure() {
        return seed;
    }

    let mut seed = [0u8; 32];

    for i in 0..4 {
        let entropy = get_entropy64();
        let offset = i * 8;
        seed[offset..offset + 8].copy_from_slice(&entropy.to_le_bytes());
    }

    seed
}

pub fn mix_entropy_into_seed(seed: &mut [u8; 32], additional: &[u8; 32]) {
    for i in 0..32 {
        seed[i] ^= additional[i];
    }

    let tsc = read_tsc();
    let tsc_bytes = tsc.to_le_bytes();
    for i in 0..8 {
        seed[i] ^= tsc_bytes[i];
        seed[i + 8] ^= tsc_bytes[i];
        seed[i + 16] ^= tsc_bytes[i];
        seed[i + 24] ^= tsc_bytes[i];
    }
}
