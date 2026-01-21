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
use super::error::CpuError;

static MSR_READS: AtomicU64 = AtomicU64::new(0);
static MSR_WRITES: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn rdmsr(msr: u32) -> u64 {
    MSR_READS.fetch_add(1, Ordering::Relaxed);

    let low: u32;
    let high: u32;

    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }

    ((high as u64) << 32) | (low as u64)
}

#[inline]
pub fn wrmsr(msr: u32, value: u64) {
    MSR_WRITES.fetch_add(1, Ordering::Relaxed);

    let low = value as u32;
    let high = (value >> 32) as u32;

    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
}

pub fn try_rdmsr(msr: u32) -> Result<u64, CpuError> {
    if msr > 0xC0002FFF && msr < 0xC0010000 {
        return Err(CpuError::InvalidMsr);
    }
    Ok(rdmsr(msr))
}

pub fn try_wrmsr(msr: u32, value: u64) -> Result<(), CpuError> {
    if msr > 0xC0002FFF && msr < 0xC0010000 {
        return Err(CpuError::InvalidMsr);
    }
    wrmsr(msr, value);
    Ok(())
}

pub fn msr_reads() -> u64 {
    MSR_READS.load(Ordering::Relaxed)
}

pub fn msr_writes() -> u64 {
    MSR_WRITES.load(Ordering::Relaxed)
}
