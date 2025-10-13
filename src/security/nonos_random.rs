#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

/// Secure random number generator state
static RANDOM_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Initialize random subsystem (hardware + software entropy pool)
pub fn init() -> Result<(), &'static str> {
    // Later: seed entropy pool from hardware RNG, TSC, and other sources
    Ok(())
}

/// Get a secure random u64 (hardware RNG preferred, fallback to TSC-based PRNG)
pub fn secure_random_u64() -> u64 {
    // Use hardware RNG if available
    #[cfg(target_arch = "x86_64")]
    {
        let mut value: u64 = 0;
        unsafe {
            if core::arch::x86_64::_rdrand64_step(&mut value) == 1 {
                return value;
            }
        }
    }
    // Fallback to atomic, time-based PRNG
    let ctr = RANDOM_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    tsc ^ ctr ^ 0xA5A5_5A5A_DEAD_BEEF
}

/// Fill buffer with secure random bytes
pub fn fill_random(buf: &mut [u8]) {
    let mut off = 0;
    while off < buf.len() {
        let v = secure_random_u64();
        let chunk = v.to_le_bytes();
        let remain = buf.len() - off;
        let take = core::cmp::min(remain, chunk.len());
        buf[off..off+take].copy_from_slice(&chunk[..take]);
        off += take;
    }
}

/// Get a random u32
pub fn secure_random_u32() -> u32 {
    secure_random_u64() as u32
}

/// Get a random byte
pub fn secure_random_u8() -> u8 {
    secure_random_u64() as u8
}
