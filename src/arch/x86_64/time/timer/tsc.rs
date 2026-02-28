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

use super::state::TSC_FREQUENCY;

pub(crate) fn rdtsc() -> u64 {
    let mut hi: u32;
    let mut lo: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

pub fn rdtscp() -> (u64, u32) {
    let mut hi: u32;
    let mut lo: u32;
    let mut aux: u32;
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nostack, preserves_flags)
        );
    }
    (((hi as u64) << 32) | (lo as u64), aux)
}

pub fn get_tsc_frequency() -> u64 {
    TSC_FREQUENCY.load(Ordering::Relaxed)
}

pub fn tsc_to_ns(tsc_ticks: u64) -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }
    (tsc_ticks * 1_000_000_000) / freq
}

pub fn ns_to_tsc(nanoseconds: u64) -> u64 {
    let freq = TSC_FREQUENCY.load(Ordering::Relaxed);
    if freq == 0 {
        return 0;
    }
    (nanoseconds * freq) / 1_000_000_000
}
