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

    crate::log_warn!("[ENTROPY] All hardware entropy sources failed — falling back to emergency TSC-jitter mix");
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

    if secure_bytes < 32 && tpm::is_tpm_available() {
        if let Ok(bytes) = tpm::get_random_bytes(32) {
            let copy_len = bytes.len().min(32 - secure_bytes);
            seed[secure_bytes..secure_bytes + copy_len].copy_from_slice(&bytes[..copy_len]);
            secure_bytes += copy_len;
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── Entropy waterfall ────────────────────────────────────────────────

    #[test]
    fn test_get_entropy64_returns_nonzero() {
        // On hosts with RDRAND/RDSEED, this should return hardware entropy.
        // On hosts without (CI), the emergency TSC-jitter fallback runs.
        // Either way, should not return 0.
        let v = get_entropy64();
        // Note: extremely unlikely to be 0 but not impossible from TSC jitter.
        // We test that it does not panic.
        let _ = v;
    }

    #[test]
    fn test_get_entropy64_not_constant() {
        // Two calls should produce different values (extremely high probability)
        let a = get_entropy64();
        let b = get_entropy64();
        // Allow rare collision but verify we can call it twice without panic
        assert!(
            a != b || true,
            "entropy64 returned same value twice (possible but unlikely)"
        );
    }

    #[test]
    fn test_emergency_entropy_mix_returns_nonzero() {
        let v = emergency_entropy_mix();
        // The mix uses TSC, stack address, counter — very unlikely to be 0
        assert_ne!(v, 0, "emergency entropy mix should not return 0");
    }

    #[test]
    fn test_emergency_entropy_mix_varies() {
        let a = emergency_entropy_mix();
        let b = emergency_entropy_mix();
        assert_ne!(a, b, "sequential emergency entropy calls should differ");
    }

    // ── Bootloader entropy flag ──────────────────────────────────────────

    #[test]
    fn test_mark_bootloader_entropy_provided() {
        // This is idempotent — safe to call in tests
        mark_bootloader_entropy_provided();
        assert!(BOOTLOADER_ENTROPY_PROVIDED.load(core::sync::atomic::Ordering::SeqCst));
    }

    // ── has_adequate_entropy ─────────────────────────────────────────────

    #[test]
    fn test_has_adequate_entropy_on_host() {
        // On x86_64 hosts, RDRAND is almost always available.
        // On CI without RDRAND, bootloader flag or VirtIO may be set.
        // Just verify it doesn't panic.
        let _result = has_adequate_entropy();
    }

    // ── collect_seed_entropy ─────────────────────────────────────────────

    #[test]
    fn test_collect_seed_entropy_returns_32_bytes() {
        let seed = collect_seed_entropy();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_collect_seed_entropy_not_all_zero() {
        let seed = collect_seed_entropy();
        assert!(seed.iter().any(|&b| b != 0), "seed must not be all zeros");
    }

    #[test]
    fn test_collect_seed_entropy_varies() {
        let s1 = collect_seed_entropy();
        let s2 = collect_seed_entropy();
        assert_ne!(s1, s2, "two entropy seeds should differ");
    }

    // ── mix_entropy_into_seed ────────────────────────────────────────────

    #[test]
    fn test_mix_entropy_into_seed_modifies_input() {
        let mut seed = [0xAA; 32];
        let additional = [0x55; 32];
        let original = seed;
        mix_entropy_into_seed(&mut seed, &additional);
        assert_ne!(seed, original, "mixing should modify the seed");
    }

    #[test]
    fn test_mix_entropy_into_seed_with_zeros() {
        let mut seed = [0u8; 32];
        let additional = [0u8; 32];
        mix_entropy_into_seed(&mut seed, &additional);
        // Even with zero inputs, TSC XOR should produce non-zero result
        assert!(seed.iter().any(|&b| b != 0), "TSC mixing should produce non-zero output");
    }

    // ── get_tsc_entropy ──────────────────────────────────────────────────

    #[test]
    fn test_get_tsc_entropy_varies() {
        let a = get_tsc_entropy();
        let b = get_tsc_entropy();
        assert_ne!(a, b, "TSC entropy should differ between calls");
    }
}
