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

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static CPUID_CALLS: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    CPUID_CALLS.fetch_add(1, Ordering::Relaxed);

    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            in("eax") leaf,
            in("ecx") 0u32,
            lateout("eax") eax,
            ebx_out = out(reg) ebx,
            lateout("ecx") ecx,
            lateout("edx") edx,
            options(nostack, preserves_flags)
        );
    }

    (eax, ebx, ecx, edx)
}

#[inline]
pub fn cpuid_count(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    CPUID_CALLS.fetch_add(1, Ordering::Relaxed);

    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            in("eax") leaf,
            in("ecx") subleaf,
            lateout("eax") eax,
            ebx_out = out(reg) ebx,
            lateout("ecx") ecx,
            lateout("edx") edx,
            options(nostack, preserves_flags)
        );
    }

    (eax, ebx, ecx, edx)
}

#[inline]
pub fn cpuid_max_leaf() -> u32 {
    let (eax, _, _, _) = cpuid(0);
    eax
}

#[inline]
pub fn cpuid_max_extended_leaf() -> u32 {
    let (eax, _, _, _) = cpuid(0x80000000);
    eax
}

pub fn cpuid_calls() -> u64 {
    CPUID_CALLS.load(Ordering::Relaxed)
}
