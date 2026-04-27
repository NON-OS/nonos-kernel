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
 * wallet/mnemonic generation. Uses aggressive multi-source collection
 * designed to work even in QEMU without virtio-rng or RDRAND:
 *
 * 1. PIT counter sampling (1.19MHz hardware timer, high-jitter)
 * 2. TSC with PIT-based variable delays (real timing jitter)
 * 3. RTC unix timestamp (unique each boot)
 * 4. Kernel millisecond timer (always increasing)
 * 5. Memory addresses (ASLR-like entropy)
 * 6. Atomic counter (monotonically increasing)
 * 7. ChaCha20 CSPRNG (if properly seeded)
 * 8. virtio-rng/RDRAND (if available)
 *
 * All sources are XORed together and hashed through BLAKE3.
 */
pub fn generate_wallet_entropy(buffer: &mut [u8]) {
    use crate::crypto::blake3_hash;
    use crate::drivers::virtio_rng;
    use core::sync::atomic::{AtomicU64, Ordering};
    static WALLET_COUNTER: AtomicU64 = AtomicU64::new(0xCAFE_BABE_DEAD_BEEF);

    #[cfg(feature = "std")]
    {
        // Host tests run in user mode and cannot access PIT I/O ports.
        // Reuse kernel RNG API, which is safe in std mode.
        rng::fill_random_bytes(buffer);
        return;
    }

    /* Collect 256 bytes of entropy from all sources */
    let mut entropy_pool = [0u8; 256];
    let mut offset = 0;

    /* Source 1: Initial TSC baseline */
    let tsc_start = read_tsc_full();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc_start.to_le_bytes());
    offset += 8;

    /* Source 2: PIT counter samples with TSC jitter measurements */
    for i in 0..16 {
        let pit = read_pit_counter_safe();
        let tsc_before = read_tsc_full();
        /* Variable delay based on PIT low bits */
        for _ in 0..((pit & 0x3F) as u32 + (i as u32 + 1) * 5) {
            core::hint::spin_loop();
        }
        let tsc_after = read_tsc_full();
        let jitter = tsc_after.wrapping_sub(tsc_before);

        /* Mix PIT, TSC, and jitter together */
        let mixed = (pit as u64) ^ jitter.rotate_left((i as u32 % 63) + 1);
        entropy_pool[offset..offset + 8].copy_from_slice(&mixed.to_le_bytes());
        offset += 8;
    }

    /* Source 3: RTC timestamp - MUST be different each boot */
    let rtc = crate::arch::x86_64::time::rtc::read_unix_timestamp();
    entropy_pool[offset..offset + 8].copy_from_slice(&rtc.to_le_bytes());
    offset += 8;

    /* Source 4: Kernel milliseconds since boot */
    let kernel_ms = crate::time::timestamp_millis();
    entropy_pool[offset..offset + 8].copy_from_slice(&kernel_ms.to_le_bytes());
    offset += 8;

    /* Source 5: Memory addresses (heap location entropy) */
    let heap_addr = entropy_pool.as_ptr() as u64;
    let stack_addr = read_stack_pointer();
    let addr_mix = heap_addr ^ stack_addr ^ (heap_addr.wrapping_mul(0x517cc1b727220a95));
    entropy_pool[offset..offset + 8].copy_from_slice(&addr_mix.to_le_bytes());
    offset += 8;

    /* Source 6: Atomic counter - ensures uniqueness even within same boot */
    let counter = WALLET_COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::SeqCst);
    let tsc_now = read_tsc_full();
    let counter_mixed = counter ^ tsc_now ^ rtc.wrapping_mul(0xBF58476D1CE4E5B9);
    entropy_pool[offset..offset + 8].copy_from_slice(&counter_mixed.to_le_bytes());
    offset += 8;

    /* Source 7: Another TSC reading after all the work */
    let tsc_mid = read_tsc_full();
    let elapsed = tsc_mid.wrapping_sub(tsc_start);
    entropy_pool[offset..offset + 8].copy_from_slice(&elapsed.to_le_bytes());
    offset += 8;

    /* Source 8: ChaCha20 RNG bytes (if initialized) */
    let mut rng_bytes = [0u8; 64];
    rng::fill_random_bytes(&mut rng_bytes);
    entropy_pool[offset..offset + 64].copy_from_slice(&rng_bytes);
    offset += 64;

    /* Source 9: virtio-rng if available (QEMU with proper config) */
    if virtio_rng::is_available() {
        let mut hw_buf = [0u8; 64];
        if virtio_rng::fill_random(&mut hw_buf).is_ok() {
            for (i, b) in entropy_pool[offset..].iter_mut().take(64).enumerate() {
                *b ^= hw_buf[i];
            }
        }
    }

    /* Source 10: RDRAND/RDSEED if available (real hardware) */
    for chunk in entropy_pool[..offset].chunks_mut(8) {
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

    /* Source 11: Final TSC with total elapsed time */
    let tsc_final = read_tsc_full();
    let total_jitter = tsc_final.wrapping_sub(tsc_start);
    let jitter_mixed = total_jitter.wrapping_mul(0x94D049BB133111EB).rotate_right(17);
    if offset + 8 <= entropy_pool.len() {
        entropy_pool[offset..offset + 8].copy_from_slice(&jitter_mixed.to_le_bytes());
    }

    /* Hash everything through BLAKE3 to produce final output */
    let hash = blake3_hash(&entropy_pool);

    /* Fill output buffer */
    if buffer.len() <= 32 {
        buffer.copy_from_slice(&hash[..buffer.len()]);
    } else {
        /* For larger buffers, use BLAKE3 in XOF mode */
        let mut hasher = blake3::Hasher::new();
        hasher.update(&entropy_pool);
        hasher.finalize_xof().fill(buffer);
    }

    /* Secure erase */
    for b in entropy_pool.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    for b in rng_bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

#[inline]
fn read_tsc_full() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    (lo as u64) | ((hi as u64) << 32)
}

#[inline]
fn read_stack_pointer() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
    }
    rsp
}

#[inline]
fn read_pit_counter_safe() -> u16 {
    const PIT_CHANNEL0: u16 = 0x40;
    const PIT_COMMAND: u16 = 0x43;
    const LATCH_CHANNEL0: u8 = 0x00;

    unsafe {
        /* Latch channel 0 */
        core::arch::asm!(
            "out dx, al",
            in("dx") PIT_COMMAND,
            in("al") LATCH_CHANNEL0,
            options(nostack, preserves_flags, nomem)
        );

        /* Read low byte */
        let low: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") low,
            in("dx") PIT_CHANNEL0,
            options(nostack, preserves_flags, nomem)
        );

        /* Read high byte */
        let high: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") high,
            in("dx") PIT_CHANNEL0,
            options(nostack, preserves_flags, nomem)
        );

        ((high as u16) << 8) | (low as u16)
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
