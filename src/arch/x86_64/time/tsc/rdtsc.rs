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

use super::state::{FEATURES, STATS_RDTSCP_CALLS, STATS_RDTSC_CALLS};
use core::sync::atomic::Ordering;

#[inline(always)]
pub fn rdtsc() -> u64 {
    let (hi, lo): (u32, u32);
    unsafe {
        core::arch::asm!("lfence", "rdtsc", "lfence", out("eax") lo, out("edx") hi, options(nostack, preserves_flags, nomem));
    }
    STATS_RDTSC_CALLS.fetch_add(1, Ordering::Relaxed);
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
pub fn rdtsc_unserialized() -> u64 {
    let (hi, lo): (u32, u32);
    unsafe {
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, preserves_flags, nomem));
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
pub fn rdtscp() -> (u64, u32) {
    let (hi, lo, aux): (u32, u32, u32);
    unsafe {
        core::arch::asm!("rdtscp", out("eax") lo, out("edx") hi, out("ecx") aux, options(nostack, preserves_flags, nomem));
    }
    STATS_RDTSCP_CALLS.fetch_add(1, Ordering::Relaxed);
    (((hi as u64) << 32) | (lo as u64), aux)
}

#[inline(always)]
pub fn read_tsc() -> u64 {
    if FEATURES.read().rdtscp_available {
        rdtscp().0
    } else {
        rdtsc()
    }
}

pub fn read_tsc_cpu() -> (u64, u32) {
    if FEATURES.read().rdtscp_available {
        rdtscp()
    } else {
        (rdtsc(), 0)
    }
}

#[inline(always)]
pub fn tsc_fence() {
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}
