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
 * Uses RDRAND as primary source (works in QEMU Haswell), with multiple
 * fallbacks including TSC jitter, PIT sampling, and RTC timestamp.
 *
 * v3: RDRAND is now primary source since virtio-rng queue has issues.
 * Each boot MUST produce a different key due to RTC + TSC jitter.
 */
pub fn generate_secure_key() -> [u8; 32] {
    let mut entropy_pool = [0u8; 256];
    let mut offset = 0;

    /* Source 1: 64 bytes from RDRAND (Haswell+ has this) */
    for _ in 0..8 {
        let val = rdrand64_or_tsc();
        entropy_pool[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }

    /* Source 2: First TSC reading */
    let tsc1 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc1.to_le_bytes());
    offset += 8;

    /* Source 3: Stack pointer XOR with heap address */
    let stack_addr = get_stack_pointer();
    let heap_entropy = entropy_pool.as_ptr() as u64;
    let mixed = stack_addr ^ heap_entropy ^ tsc1;
    entropy_pool[offset..offset + 8].copy_from_slice(&mixed.to_le_bytes());
    offset += 8;

    /* Source 4: More RDRAND with jitter delays */
    for i in 0..4 {
        for _ in 0..(i + 1) * 10 {
            core::hint::spin_loop();
        }
        let val = rdrand64_or_tsc();
        entropy_pool[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }

    /* Source 5: 8 PIT counter samples with delays */
    for i in 0..8 {
        let pit_val = read_pit_counter();
        entropy_pool[offset..offset + 2].copy_from_slice(&pit_val.to_le_bytes());
        offset += 2;
        for _ in 0..(i + 1) * 5 {
            core::hint::spin_loop();
        }
    }

    /* Source 6: Second TSC - captures timing jitter */
    let tsc2 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc2.to_le_bytes());
    offset += 8;

    /* Source 7: TSC delta (highly variable) */
    let jitter = tsc2.wrapping_sub(tsc1);
    entropy_pool[offset..offset + 8].copy_from_slice(&jitter.to_le_bytes());
    offset += 8;

    /* Source 8: RTC unix timestamp - DIFFERENT EACH BOOT */
    let rtc_time = read_rtc_timestamp();
    entropy_pool[offset..offset + 8].copy_from_slice(&rtc_time.to_le_bytes());
    offset += 8;

    /* Source 9: Kernel millisecond timer */
    let kernel_ms = crate::time::timestamp_millis();
    entropy_pool[offset..offset + 8].copy_from_slice(&kernel_ms.to_le_bytes());
    offset += 8;

    /* Source 10: ChaCha20 RNG bytes */
    let mut rng_bytes = [0u8; 32];
    rng::fill_random_bytes(&mut rng_bytes);
    entropy_pool[offset..offset + 32].copy_from_slice(&rng_bytes);
    offset += 32;

    /* Source 11: Third TSC reading */
    let tsc3 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc3.to_le_bytes());
    offset += 8;

    /* Source 12: More jitter */
    let jitter2 = tsc3.wrapping_sub(tsc2);
    entropy_pool[offset..offset + 8].copy_from_slice(&jitter2.to_le_bytes());
    offset += 8;

    /* Source 13: Final RDRAND burst */
    for _ in 0..4 {
        let val = rdrand64_or_tsc();
        entropy_pool[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        offset += 8;
    }

    /* Source 14: Global counter - ensures uniqueness even within same boot */
    let counter = KEYGEN_COUNTER.fetch_add(0xA3B7_C1D5_E9F2_4680, Ordering::SeqCst);
    entropy_pool[offset..offset + 8].copy_from_slice(&counter.to_le_bytes());

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
    /* Fallback: TSC XOR with incrementing counter for uniqueness */
    let tsc = read_tsc();
    let ctr = KEYGEN_COUNTER.fetch_add(1, Ordering::Relaxed);
    tsc ^ ctr
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
