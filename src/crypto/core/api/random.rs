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
 * Collects ~160 bytes from 12 different sources and mixes through BLAKE3.
 * This approach ensures unique keys even when the system RNG state is
 * predictable (e.g., shortly after boot or in virtualized environments).
 */
pub fn generate_secure_key() -> [u8; 32] {
    let mut entropy_pool = [0u8; 168];
    let mut offset = 0;

    /* Source 1: First TSC reading */
    let tsc1 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc1.to_le_bytes());
    offset += 8;

    /* Source 2: Stack pointer address */
    let stack_addr = get_stack_pointer();
    entropy_pool[offset..offset + 8].copy_from_slice(&stack_addr.to_le_bytes());
    offset += 8;

    /* Source 3: 16 PIT counter samples with small delays between each */
    for _ in 0..16 {
        let pit_val = read_pit_counter();
        entropy_pool[offset..offset + 2].copy_from_slice(&pit_val.to_le_bytes());
        offset += 2;
        for _ in 0..3 {
            core::hint::spin_loop();
        }
    }

    /* Source 4: Second TSC reading */
    let tsc2 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc2.to_le_bytes());
    offset += 8;

    /* Source 5: Jitter between first and second TSC */
    let jitter1 = tsc2.wrapping_sub(tsc1);
    entropy_pool[offset..offset + 8].copy_from_slice(&jitter1.to_le_bytes());
    offset += 8;

    /* Source 6: RTC wall clock time as unix timestamp */
    let rtc_time = read_rtc_timestamp();
    entropy_pool[offset..offset + 8].copy_from_slice(&rtc_time.to_le_bytes());
    offset += 8;

    /* Source 7: First 32-byte pull from ChaCha20 RNG */
    let mut rng_bytes1 = [0u8; 32];
    rng::fill_random_bytes(&mut rng_bytes1);
    entropy_pool[offset..offset + 32].copy_from_slice(&rng_bytes1);
    offset += 32;

    /* Source 8: Third TSC reading */
    let tsc3 = read_tsc();
    entropy_pool[offset..offset + 8].copy_from_slice(&tsc3.to_le_bytes());
    offset += 8;

    /* Source 9: Jitter between second and third TSC */
    let jitter2 = tsc3.wrapping_sub(tsc2);
    entropy_pool[offset..offset + 8].copy_from_slice(&jitter2.to_le_bytes());
    offset += 8;

    /* Source 10: Buffer address (varies with allocator state) */
    let buf_addr = entropy_pool.as_ptr() as u64;
    entropy_pool[offset..offset + 8].copy_from_slice(&buf_addr.to_le_bytes());
    offset += 8;

    /* Source 11: Second 32-byte pull from ChaCha20 RNG */
    let mut rng_bytes2 = [0u8; 32];
    rng::fill_random_bytes(&mut rng_bytes2);
    entropy_pool[offset..offset + 32].copy_from_slice(&rng_bytes2);
    offset += 32;

    /* Source 12: Global counter with non-zero starting value */
    let counter = KEYGEN_COUNTER.fetch_add(0xA3B7_C1D5_E9F2_4680, Ordering::SeqCst);
    entropy_pool[offset..offset + 8].copy_from_slice(&counter.to_le_bytes());

    /* Mix all 168 bytes through BLAKE3 to produce final 32-byte key */
    let key = blake3_hash(&entropy_pool);

    /* Securely erase entropy pool from stack */
    for byte in entropy_pool.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in rng_bytes1.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in rng_bytes2.iter_mut() {
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);

    key
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
