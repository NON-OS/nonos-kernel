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

/*
 * Timing Attack Protection.
 *
 * Prevents timing-based side-channel attacks on cryptographic operations:
 * - Constant-time comparisons (no early exit)
 * - Random delays to mask operation timing
 * - Jitter injection for signature verification
 *
 * Critical for: key validation, signature checks, proof verification.
 */

use core::sync::atomic::{AtomicU64, Ordering};

static JITTER_SEED: AtomicU64 = AtomicU64::new(0);

pub fn init_jitter(entropy: u64) {
    JITTER_SEED.store(entropy, Ordering::Release);
}

fn next_jitter() -> u64 {
    let seed = JITTER_SEED.load(Ordering::Acquire);
    let next = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    JITTER_SEED.store(next, Ordering::Release);
    next
}

pub fn add_random_delay() {
    let jitter = next_jitter() & 0xFFFF;
    for _ in 0..jitter {
        core::hint::spin_loop();
    }
}

pub fn add_fixed_delay(iterations: u32) {
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

#[inline(never)]
pub fn constant_time_select(condition: bool, a: u64, b: u64) -> u64 {
    let mask = if condition { u64::MAX } else { 0 };
    (a & mask) | (b & !mask)
}

#[inline(never)]
pub fn constant_time_is_zero(value: u64) -> bool {
    let v = value | value.wrapping_neg();
    (v >> 63) == 0
}

#[inline(never)]
pub fn constant_time_eq_u8(a: u8, b: u8) -> bool {
    let diff = a ^ b;
    constant_time_is_zero(diff as u64)
}

#[inline(never)]
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        add_random_delay();
        return false;
    }

    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }

    add_random_delay();
    diff == 0
}

pub struct TimingGuard {
    min_cycles: u64,
    start: u64,
}

impl TimingGuard {
    pub fn new(min_microseconds: u64) -> Self {
        let start = read_tsc();
        Self {
            min_cycles: min_microseconds * 2000,
            start,
        }
    }

    fn elapsed(&self) -> u64 {
        read_tsc().saturating_sub(self.start)
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        let elapsed = self.elapsed();
        if elapsed < self.min_cycles {
            let remaining = self.min_cycles - elapsed;
            for _ in 0..remaining {
                core::hint::spin_loop();
            }
        }
        add_random_delay();
    }
}

fn read_tsc() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}
