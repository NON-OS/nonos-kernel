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

/*
 * High-level random number generation API.
 *
 * These functions provide a convenient interface over the underlying
 * ChaCha20-based CSPRNG. They're suitable for general-purpose random
 * byte generation but not for cryptographic key generation (use
 * generate_secure_key() for that, which collects fresh entropy).
 */

use super::error::{CryptoError, CryptoResult};
use super::util::rng;

pub fn fill_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    Ok(())
}

pub fn get_bytes(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    Ok(())
}

/*
 * Fills buffer with random bytes if it can hold at least min_entropy bits.
 * This is a sanity check to prevent accidentally using a tiny buffer
 * for security-sensitive operations that need more entropy.
 */
pub fn get_bytes_checked(buffer: &mut [u8], min_entropy: usize) -> CryptoResult<()> {
    if buffer.len() < min_entropy / 8 {
        return Err(CryptoError::BufferTooSmall);
    }
    rng::fill_random_bytes(buffer);
    Ok(())
}

/*
 * get_bytes_secure uses hardware entropy when available but falls
 * back gracefully if not. returns error only if rng completely fails.
 */
pub fn get_bytes_secure(buffer: &mut [u8]) -> CryptoResult<()> {
    rng::fill_random_bytes(buffer);
    mix_hardware_entropy(buffer);
    Ok(())
}

/*
 * generate_wallet_entropy is the production-ready entropy function for
 * wallet/mnemonic generation. uses aggressive multi-source collection:
 *
 * 1. virtio-rng (qemu gives true randomness from host /dev/urandom)
 * 2. rdrand/rdseed (intel/amd hardware rng on real cpus)
 * 3. chacha20 csprng (seeded from bootloader entropy)
 * 4. tsc jitter (timing variance as additional mixing)
 *
 * all sources are xored together so any single good source is enough
 * to produce unique keys. this is how real os kernels do it.
 */
pub fn generate_wallet_entropy(buffer: &mut [u8]) {
    use crate::drivers::virtio_rng;
    use crate::crypto::blake3_hash;
    use core::sync::atomic::{AtomicU64, Ordering};
    static WALLET_COUNTER: AtomicU64 = AtomicU64::new(0xCAFE_BABE_DEAD_BEEF);

    rng::fill_random_bytes(buffer);

    if virtio_rng::is_available() {
        let mut hw_buf = [0u8; 64];
        if virtio_rng::fill_random(&mut hw_buf).is_ok() {
            for (i, b) in buffer.iter_mut().enumerate() {
                *b ^= hw_buf[i % 64];
            }
        }
    }

    for chunk in buffer.chunks_mut(8) {
        for _ in 0..20 {
            if let Some(v) = rng::try_rdseed64() {
                let bytes = v.to_le_bytes();
                for (i, b) in chunk.iter_mut().enumerate() { *b ^= bytes[i]; }
                break;
            }
            if let Some(v) = rng::try_rdrand64() {
                let bytes = v.to_le_bytes();
                for (i, b) in chunk.iter_mut().enumerate() { *b ^= bytes[i]; }
                break;
            }
            for _ in 0..50 { core::hint::spin_loop(); }
        }
    }

    let rtc = crate::arch::x86_64::time::rtc::read_unix_timestamp();
    let rtc_bytes = rtc.to_le_bytes();
    for (i, b) in buffer.iter_mut().enumerate() {
        *b ^= rtc_bytes[i % 8];
    }

    let counter = WALLET_COUNTER.fetch_add(0x1234_5678_9ABC_DEF0, Ordering::SeqCst);
    let counter_bytes = counter.to_le_bytes();
    for (i, b) in buffer.iter_mut().enumerate() {
        *b ^= counter_bytes[i % 8];
    }

    let kernel_ms = crate::time::timestamp_millis();
    let ms_bytes = kernel_ms.to_le_bytes();
    for (i, b) in buffer.iter_mut().enumerate() {
        *b ^= ms_bytes[i % 8];
    }

    let mut tsc_mix = [0u8; 32];
    for i in 0..4 {
        let t1: u64;
        unsafe { core::arch::asm!("rdtsc", out("eax") _, out("edx") _, options(nomem, nostack)); }
        unsafe { core::arch::asm!("rdtsc", out("eax") t1, lateout("edx") _, options(nomem, nostack)); }
        for _ in 0..((i * 7) + 3) { core::hint::spin_loop(); }
        let t2: u64;
        unsafe { core::arch::asm!("rdtsc", out("eax") t2, lateout("edx") _, options(nomem, nostack)); }
        let jitter = t2.wrapping_sub(t1).wrapping_mul(0x9E3779B97F4A7C15);
        tsc_mix[i * 8..(i + 1) * 8].copy_from_slice(&jitter.to_le_bytes());
    }
    for (i, b) in buffer.iter_mut().enumerate() {
        *b ^= tsc_mix[i % 32];
    }

    if buffer.len() == 16 || buffer.len() == 32 {
        let mixed = blake3_hash(buffer);
        buffer.copy_from_slice(&mixed[..buffer.len()]);
    }
}

/*
 * pulls fresh entropy from all available hardware sources and xors
 * into buffer. uses virtio-rng first (best entropy in qemu), then
 * rdrand/rdseed as fallback on real hardware.
 */
fn mix_hardware_entropy(buffer: &mut [u8]) {
    use crate::drivers::virtio_rng;

    /* try virtio-rng first - gives true randomness in qemu */
    if virtio_rng::is_available() {
        let mut hw_buf = [0u8; 64];
        if virtio_rng::fill_random(&mut hw_buf).is_ok() {
            for (i, b) in buffer.iter_mut().enumerate() {
                *b ^= hw_buf[i % 64];
            }
        }
    }

    /* rdrand/rdseed on real hardware */
    if rng::has_rdrand() || rng::has_rdseed() {
        for chunk in buffer.chunks_mut(8) {
            if let Some(v) = rng::try_rdseed64() {
                let bytes = v.to_le_bytes();
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= bytes[i];
                }
            } else if let Some(v) = rng::try_rdrand64() {
                let bytes = v.to_le_bytes();
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b ^= bytes[i];
                }
            }
        }
    }
}
