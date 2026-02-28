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

use super::state::{RDRAND_RETRY_LIMIT, RDSEED_RETRY_LIMIT};

#[cfg(target_arch = "x86_64")]
pub fn try_rdrand64() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }

    for _ in 0..RDRAND_RETRY_LIMIT {
        // SAFETY: RDRAND verified available via CPUID.
        unsafe {
            let mut val: u64;
            let mut success: u8;
            core::arch::asm!(
                "rdrand {val}",
                "setc {success}",
                val = out(reg) val,
                success = out(reg_byte) success,
                options(nomem, nostack, preserves_flags)
            );
            if success != 0 {
                return Some(val);
            }
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(target_arch = "x86_64")]
pub fn try_rdseed64() -> Option<u64> {
    if !has_rdseed() {
        return None;
    }

    for _ in 0..RDSEED_RETRY_LIMIT {
        // SAFETY: RDSEED verified available via CPUID.
        unsafe {
            let mut val: u64;
            let mut success: u8;
            core::arch::asm!(
                "rdseed {val}",
                "setc {success}",
                val = out(reg) val,
                success = out(reg_byte) success,
                options(nomem, nostack, preserves_flags)
            );
            if success != 0 {
                return Some(val);
            }
        }
        core::hint::spin_loop();
    }
    None
}

#[cfg(target_arch = "x86_64")]
pub fn has_rdrand() -> bool {
    // SAFETY: CPUID is a valid x86_64 instruction.
    unsafe {
        let ecx: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
            options(nomem)
        );
        (ecx & (1 << 30)) != 0
    }
}

#[cfg(target_arch = "x86_64")]
pub fn has_rdseed() -> bool {
    // SAFETY: CPUID is a valid x86_64 instruction.
    unsafe {
        let ebx_val: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            ebx_out = out(reg) ebx_val,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nomem)
        );
        (ebx_val & (1 << 18)) != 0
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn read_tsc() -> u64 {
    // SAFETY: RDTSC is a valid x86_64 instruction.
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        (lo as u64) | ((hi as u64) << 32)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn try_rdrand64() -> Option<u64> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn try_rdseed64() -> Option<u64> {
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn has_rdrand() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
pub fn has_rdseed() -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn read_tsc() -> u64 {
    0
}
