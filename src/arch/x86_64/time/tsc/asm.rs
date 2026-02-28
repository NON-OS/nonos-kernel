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
use super::state::{FEATURES, STATS_RDTSC_CALLS, STATS_RDTSCP_CALLS};

#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    // SAFETY: Caller must ensure port is valid I/O port.
    unsafe {
        let value: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, preserves_flags, nomem)
        );
        value
    }
}

#[inline]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Caller must ensure port is valid I/O port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("al") value,
            in("dx") port,
            options(nostack, preserves_flags, nomem)
        );
    }
}

#[inline(always)]
pub fn rdtsc() -> u64 {
    let hi: u32;
    let lo: u32;
    // SAFETY: RDTSC is a safe, unprivileged x86 instruction.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            "lfence",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    STATS_RDTSC_CALLS.fetch_add(1, Ordering::Relaxed);
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
pub fn rdtsc_unserialized() -> u64 {
    let hi: u32;
    let lo: u32;
    // SAFETY: RDTSC is a safe, unprivileged x86 instruction.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags, nomem)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
pub fn rdtscp() -> (u64, u32) {
    let hi: u32;
    let lo: u32;
    let aux: u32;
    // SAFETY: RDTSCP is a safe, unprivileged x86 instruction (when available).
    unsafe {
        core::arch::asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nostack, preserves_flags, nomem)
        );
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
    // SAFETY: MFENCE is a safe, unprivileged x86 instruction.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

pub fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is a safe, unprivileged x86 instruction.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

pub fn cpuid_max_leaf() -> u32 {
    cpuid(0, 0).0
}

pub fn cpuid_max_extended_leaf() -> u32 {
    cpuid(0x80000000, 0).0
}
