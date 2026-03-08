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
use crate::drivers::virtio_rng;
use crate::drivers::tpm;

pub fn init_entropy() -> Result<(), EntropyError> {
    if virtio_rng::is_available() {
        HARDWARE_ENTROPY_VERIFIED.store(true, Ordering::SeqCst);
        return Ok(());
    }

    if has_rdrand() || has_rdseed() {
        HARDWARE_ENTROPY_VERIFIED.store(true, Ordering::SeqCst);
        return Ok(());
    }

    if tpm::is_tpm_available() {
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
    virtio_rng::is_available() || has_rdrand() || has_rdseed() || tpm::is_tpm_available() || BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::Acquire)
}

pub fn verify_entropy_sources() -> Result<(), EntropyError> {
    if virtio_rng::is_available() {
        return Ok(());
    }

    if has_rdrand() || has_rdseed() {
        return Ok(());
    }

    if tpm::is_tpm_available() {
        return Ok(());
    }

    if BOOTLOADER_ENTROPY_PROVIDED.load(Ordering::Acquire) {
        return Ok(());
    }

    Err(EntropyError::NoHardwareSource)
}

pub fn get_entropy64_secure() -> Result<u64, EntropyError> {
    if virtio_rng::is_available() {
        let mut buf = [0u8; 8];
        if virtio_rng::fill_random(&mut buf).is_ok() {
            return Ok(u64::from_le_bytes(buf));
        }
    }

    if let Some(v) = try_rdseed64() {
        return Ok(v);
    }

    if let Some(v) = try_rdrand64() {
        return Ok(v);
    }

    if tpm::is_tpm_available() {
        if let Ok(bytes) = tpm::get_random_bytes(8) {
            if bytes.len() >= 8 {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[..8]);
                return Ok(u64::from_le_bytes(buf));
            }
        }
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
    let tsc1 = read_tsc();

    let stack_addr: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack_addr, options(nomem, nostack));
    }

    for _ in 0..counter.wrapping_rem(16).wrapping_add(1) {
        core::hint::spin_loop();
    }
    let tsc2 = read_tsc();

    let jitter = tsc2.wrapping_sub(tsc1);

    let mut state = counter;
    state = state.wrapping_add(0x9e3779b97f4a7c15);
    state ^= tsc1;
    state = (state ^ (state >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    state ^= stack_addr;
    state = (state ^ (state >> 27)).wrapping_mul(0x94d049bb133111eb);
    state ^= jitter;
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

    if virtio_rng::is_available() {
        if virtio_rng::fill_random(&mut seed).is_ok() {
            return Ok(seed);
        }
    }

    let mut offset = 0;

    while offset < 32 {
        if let Some(v) = try_rdseed64() {
            let len = core::cmp::min(8, 32 - offset);
            seed[offset..offset + len].copy_from_slice(&v.to_le_bytes()[..len]);
            offset += len;
        } else {
            break;
        }
    }

    while offset < 32 {
        for _ in 0..10 {
            if let Some(v) = try_rdrand64() {
                let len = core::cmp::min(8, 32 - offset);
                seed[offset..offset + len].copy_from_slice(&v.to_le_bytes()[..len]);
                offset += len;
                break;
            }
            for _ in 0..50 { core::hint::spin_loop(); }
        }
        if offset < 32 {
            let t1 = read_tsc();
            for _ in 0..((t1 & 0x1F) + 1) { core::hint::spin_loop(); }
            let t2 = read_tsc();
            let len = core::cmp::min(8, 32 - offset);
            seed[offset..offset + len].copy_from_slice(&t2.wrapping_sub(t1).to_le_bytes()[..len]);
            offset += len;
        }
    }

    if tpm::is_tpm_available() {
        if let Ok(bytes) = tpm::get_random_bytes(32) {
            for i in 0..bytes.len().min(32) { seed[i] ^= bytes[i]; }
        }
    }

    let stack_addr: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) stack_addr, options(nomem, nostack)); }
    let counter = ENTROPY_COUNTER.fetch_add(0xA7B3_C5D9_E1F4_2680, Ordering::SeqCst);
    let sb = stack_addr.to_le_bytes();
    let cb = counter.to_le_bytes();
    for i in 0..8 {
        seed[i] ^= sb[i];
        seed[i + 8] ^= cb[i];
        seed[i + 16] ^= sb[7 - i];
        seed[i + 24] ^= cb[7 - i];
    }
    let tb = read_tsc().to_le_bytes();
    for i in 0..8 { seed[i] ^= tb[i]; }

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

    let stack_addr: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) stack_addr, options(nomem, nostack));
    }
    let stack_bytes = stack_addr.to_le_bytes();
    for i in 0..8 {
        seed[i] ^= stack_bytes[i];
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
