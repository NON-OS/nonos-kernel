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

use core::sync::atomic::{AtomicU64, Ordering};
use crate::crypto::util::rng;
use crate::crypto::blake3_hash;

/*
 * Non-zero starting value for the global entropy counter. Using a prime
 * number to avoid patterns when XORed with other entropy sources. This
 * ensures the counter contributes unique bits even on first use.
 */
static KEYGEN_COUNTER: AtomicU64 = AtomicU64::new(0xB5A1_9E37_C4D2_8F6B);

pub fn secure_random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    rng::fill_random_bytes(&mut bytes);
    u32::from_le_bytes(bytes)
}

pub fn secure_random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    rng::fill_random_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub fn secure_random_u8() -> u8 {
    let mut bytes = [0u8; 1];
    rng::fill_random_bytes(&mut bytes);
    bytes[0]
}

pub fn fill_random(buf: &mut [u8]) {
    rng::fill_random_bytes(buf);
}

/*
 * Generates a 32-byte cryptographic key using aggressive entropy collection.
 *
 * v5: Added VIRTIO-RNG support for true randomness in QEMU.
 * In QEMU: Start with `-device virtio-rng-pci` for guaranteed unique keys.
 * Without virtio-rng, falls back to timing-based entropy which may be
 * deterministic across VM restarts from the same snapshot.
 *
 * Each call MUST produce a different key even if hardware RNG fails.
 */
pub fn generate_secure_key() -> [u8; 32] {
    use crate::drivers::virtio_rng;

    let mut entropy_pool = [0u8; 256];
    let mut offset = 0;
    let mut has_true_randomness = false;

    /* CRITICAL: Try virtio-rng FIRST - this gives TRUE randomness in QEMU
     * from the host's /dev/urandom. This is the ONLY reliable entropy
     * source in a VM without hardware RNG. */
    if virtio_rng::is_available() {
        let mut virt_buf = [0u8; 64];
        if virtio_rng::fill_random(&mut virt_buf).is_ok() {
            entropy_pool[offset..offset + 64].copy_from_slice(&virt_buf);
            offset += 64;
            has_true_randomness = true;
            /* Scrub */
            for b in virt_buf.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0) };
            }
        }
    }

    /* Capture initial TSC for timing baseline */
    let tsc_start = read_tsc();

    /* Source 1: 64 bytes from RDRAND (Haswell+ has this) */
    for _ in 0..8 {
        let val = rdrand64_or_tsc();
        entropy_pool[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }

    /* Source 2: First TSC reading after RDRAND work */
    let tsc1 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc1.to_le_bytes());
    offset += 8;

    /* Source 3: Stack pointer XOR with heap address and initial delta */
    let stack_addr = get_stack_pointer();
    let heap_entropy = entropy_pool.as_ptr() as u64;
    let initial_jitter = tsc1.wrapping_sub(tsc_start);
    let mixed = stack_addr ^ heap_entropy ^ tsc1 ^ initial_jitter.wrapping_mul(0x517cc1b727220a95);
    entropy_pool[offset..offset + 8].copy_from_slice(&mixed.to_le_bytes());
    offset += 8;

    /* Source 4: More RDRAND with PIT-based jitter delays.
     * Use PIT counter as delay source - actual hardware timing varies. */
    for i in 0..4 {
        /* Read PIT and use low bits for variable delay */
        let pit_delay = read_pit_counter();
        let delay_loops = ((pit_delay as u32) & 0xFF).wrapping_add((i as u32 + 1) * 50);
        for _ in 0..delay_loops {
            core::hint::spin_loop();
        }
        let val = rdrand64_or_tsc();
        entropy_pool[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }

    /* Source 5: 8 PIT counter samples with timing measurements.
     * PIT decrements at ~1.19MHz, so readings vary based on exact timing. */
    for i in 0..8 {
        let pit_val = read_pit_counter();
        entropy_pool[offset..offset + 2].copy_from_slice(&pit_val.to_le_bytes());
        offset += 2;
        /* Variable delay based on previous PIT reading */
        for _ in 0..((pit_val & 0x3F) as u32 + (i as u32 + 1) * 10) {
            core::hint::spin_loop();
        }
    }

    /* Source 6: Second TSC - captures accumulated timing jitter */
    let tsc2 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc2.to_le_bytes());
    offset += 8;

    /* Source 7: TSC delta with nonlinear mixing */
    let jitter = tsc2.wrapping_sub(tsc1);
    let mixed_jitter = jitter.wrapping_mul(0x9E3779B97F4A7C15).rotate_right((jitter & 31) as u32);
    entropy_pool[offset..offset + 8].copy_from_slice(&mixed_jitter.to_le_bytes());
    offset += 8;

    /* Source 8: RTC unix timestamp - DIFFERENT EACH BOOT */
    let rtc_time = read_rtc_timestamp();
    entropy_pool[offset..offset + 8].copy_from_slice(&rtc_time.to_le_bytes());
    offset += 8;

    /* Source 9: Kernel millisecond timer XORed with PIT for sub-ms entropy */
    let kernel_ms = crate::time::timestamp_millis();
    let pit_now = read_pit_counter() as u64;
    let time_entropy = kernel_ms ^ (pit_now << 48) ^ (pit_now << 32) ^ (pit_now << 16);
    entropy_pool[offset..offset + 8].copy_from_slice(&time_entropy.to_le_bytes());
    offset += 8;

    /* Source 10: ChaCha20 RNG bytes */
    let mut rng_bytes = [0u8; 32];
    rng::fill_random_bytes(&mut rng_bytes);
    entropy_pool[offset..offset + 32].copy_from_slice(&rng_bytes);
    offset += 32;

    /* Source 11: Third TSC reading with another PIT-based delay */
    let pit_for_delay = read_pit_counter();
    for _ in 0..(pit_for_delay & 0x7F) as u32 {
        core::hint::spin_loop();
    }
    let tsc3 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc3.to_le_bytes());
    offset += 8;

    /* Source 12: Combined jitter from all TSC measurements */
    let jitter2 = tsc3.wrapping_sub(tsc2);
    let total_jitter = tsc3.wrapping_sub(tsc_start);
    let combined = jitter2 ^ total_jitter.rotate_left(17) ^ jitter.rotate_right(23);
    entropy_pool[offset..offset + 8].copy_from_slice(&combined.to_le_bytes());

    /* Log warning if no true randomness available */
    if !has_true_randomness {
        crate::log_warn!("crypto: No virtio-rng! Add -device virtio-rng-pci to QEMU for unique wallets");
    }
    offset += 8;

    /* Source 13: Final RDRAND burst with variable PIT-based delays */
    for i in 0..4 {
        let pit_d = read_pit_counter();
        for _ in 0..(pit_d & 0x1F) as u32 + i * 8 {
            core::hint::spin_loop();
        }
        let val = rdrand64_or_tsc();
        entropy_pool[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }

    /* Source 14: Global counter - ensures uniqueness even within same boot.
     * XOR with final TSC to add timing dependency. */
    let counter = KEYGEN_COUNTER.fetch_add(0xA3B7_C1D5_E9F2_4680, Ordering::SeqCst);
    let tsc_final = read_tsc();
    let counter_mixed = counter ^ tsc_final ^ tsc_final.wrapping_sub(tsc_start);
    entropy_pool[offset..offset + 8].copy_from_slice(&counter_mixed.to_le_bytes());

    /* Mix through BLAKE3 */
    let key = blake3_hash(&entropy_pool);

    /* Secure erase */
    for byte in entropy_pool.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in rng_bytes.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    key
}

#[inline]
fn rdrand64_or_tsc() -> u64 {
    /* Try RDRAND up to 10 times, fall back to TSC XOR with counter */
    for _ in 0..10 {
        let mut val: u64 = 0;
        let success: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) val,
                out(reg_byte) success,
                options(nostack)
            );
        }
        if success != 0 && val != 0 {
            return val;
        }
    }
    /* Fallback: TSC XOR with incrementing counter AND PIT for more entropy.
     * QEMU's RDRAND can fail, and TSC alone might not have enough jitter. */
    let tsc = read_tsc();
    let pit = read_pit_counter() as u64;
    let ctr = KEYGEN_COUNTER.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    tsc ^ ctr ^ (pit << 32) ^ (pit << 16)
}

pub fn generate_secure_key_checked() -> Result<[u8; 32], &'static str> {
    let mut key = [0u8; 32];
    rng::fill_random_bytes_secure(&mut key)
        .map_err(|_| "Insufficient entropy for key generation")?;
    Ok(key)
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn read_tsc() -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        (lo as u64) | ((hi as u64) << 32)
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn read_tsc() -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn get_stack_pointer() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
    }
    rsp
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn get_stack_pointer() -> u64 {
    0
}

#[cfg(target_arch = "x86_64")]
fn read_pit_counter() -> u16 {
    /* PIT Channel 0 latch and read */
    const PIT_CHANNEL0: u16 = 0x40;
    const PIT_COMMAND: u16 = 0x43;
    const LATCH_CHANNEL0: u8 = 0x00;

    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") PIT_COMMAND,
            in("al") LATCH_CHANNEL0,
            options(nostack, preserves_flags, nomem)
        );

        let low: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") low,
            in("dx") PIT_CHANNEL0,
            options(nostack, preserves_flags, nomem)
        );

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

#[cfg(not(target_arch = "x86_64"))]
fn read_pit_counter() -> u16 {
    0
}

fn read_rtc_timestamp() -> u64 {
    crate::arch::x86_64::time::rtc::read_unix_timestamp()
}
