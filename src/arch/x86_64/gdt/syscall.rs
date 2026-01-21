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
use core::sync::atomic::Ordering;
use crate::arch::x86_64::gdt::constants::*;
use crate::arch::x86_64::gdt::state::SYSCALL_SETUPS;

/// # Safety
/// Entry point must be a valid syscall handler.
pub unsafe fn setup_syscall(entry_point: u64, rflags_mask: u64) { unsafe {
    let efer_lo: u32;
    let efer_hi: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_EFER,
        out("eax") efer_lo,
        out("edx") efer_hi,
        options(nomem, nostack, preserves_flags)
    );

    let efer = ((efer_hi as u64) << 32) | (efer_lo as u64);
    let new_efer = efer | EFER_SCE;

    asm!(
        "wrmsr",
        in("ecx") MSR_EFER,
        in("eax") new_efer as u32,
        in("edx") (new_efer >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    let star: u64 = (0x10u64 << 48) | (0x08u64 << 32);
    asm!(
        "wrmsr",
        in("ecx") MSR_STAR,
        in("eax") star as u32,
        in("edx") (star >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    asm!(
        "wrmsr",
        in("ecx") MSR_LSTAR,
        in("eax") entry_point as u32,
        in("edx") (entry_point >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    asm!(
        "wrmsr",
        in("ecx") MSR_SFMASK,
        in("eax") rflags_mask as u32,
        in("edx") (rflags_mask >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    SYSCALL_SETUPS.fetch_add(1, Ordering::Relaxed);
}}
