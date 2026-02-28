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

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use x86_64::registers::model_specific::Msr;

pub static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub static X2APIC_MODE: AtomicBool = AtomicBool::new(false);
pub static TSC_DEADLINE_MODE: AtomicBool = AtomicBool::new(false);
pub static MMIO_BASE: AtomicU32 = AtomicU32::new(0);
pub static CACHED_ID: AtomicU32 = AtomicU32::new(0);
pub static CURRENT_TPR: AtomicU8 = AtomicU8::new(0);

#[inline(always)]
pub fn rdmsr(msr: u32) -> u64 {
    unsafe { Msr::new(msr).read() }
}

#[inline(always)]
pub fn wrmsr(msr: u32, val: u64) {
    unsafe { Msr::new(msr).write(val) }
}

#[inline(always)]
pub fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

pub fn has_xapic() -> bool {
    let (_, _, _, edx) = cpuid(1, 0);
    (edx & (1 << 9)) != 0
}

pub fn has_x2apic() -> bool {
    let (_, _, ecx, _) = cpuid(1, 0);
    (ecx & (1 << 21)) != 0
}

pub fn has_tsc_deadline() -> bool {
    let (_, _, ecx, _) = cpuid(1, 0);
    (ecx & (1 << 24)) != 0
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn is_x2apic() -> bool {
    X2APIC_MODE.load(Ordering::Acquire)
}

#[inline]
pub fn supports_tsc_deadline() -> bool {
    TSC_DEADLINE_MODE.load(Ordering::Acquire)
}
