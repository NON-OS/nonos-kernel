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
use crate::arch::x86_64::gdt::constants::*;

/// # Safety
/// Address must point to valid memory.
#[inline]
pub unsafe fn set_fs_base(addr: u64) { unsafe {
    let low = addr as u32;
    let high = (addr >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") MSR_FS_BASE,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}}

#[inline]
pub unsafe fn get_fs_base() -> u64 { unsafe {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_FS_BASE,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}}

/// # Safety
/// Address must point to valid memory.
#[inline]
pub unsafe fn set_gs_base(addr: u64) { unsafe {
    let low = addr as u32;
    let high = (addr >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") MSR_GS_BASE,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}}

#[inline]
pub unsafe fn get_gs_base() -> u64 { unsafe {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_GS_BASE,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}}

/// # Safety
/// Address must point to valid per-CPU data.
#[inline]
pub unsafe fn set_kernel_gs_base(addr: u64) { unsafe {
    let low = addr as u32;
    let high = (addr >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") MSR_KERNEL_GS_BASE,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}}

#[inline]
pub unsafe fn get_kernel_gs_base() -> u64 { unsafe {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_KERNEL_GS_BASE,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}}

/// # Safety
/// Must only be called at syscall/interrupt entry/exit boundaries.
#[inline]
pub unsafe fn swapgs() { unsafe {
    asm!("swapgs", options(nomem, nostack, preserves_flags));
}}
