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

use core::arch::asm;

pub fn read_msr(msr: u32) -> u64 {
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

pub fn write_msr(msr: u32, value: u64) {
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

pub fn rdfsbase() -> u64 {
    let val: u64;
    unsafe {
        asm!("rdfsbase {}", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

pub fn wrfsbase(val: u64) {
    unsafe {
        asm!("wrfsbase {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

pub fn rdgsbase() -> u64 {
    let val: u64;
    unsafe {
        asm!("rdgsbase {}", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

pub fn wrgsbase(val: u64) {
    unsafe {
        asm!("wrgsbase {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

pub fn swapgs() {
    unsafe {
        asm!("swapgs", options(nomem, nostack, preserves_flags));
    }
}

pub fn check_fsgsbase_support() -> bool {
    let result: u32;
    unsafe {
        asm!(
            "push rbx",
            "mov eax, 7",
            "xor ecx, ecx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) result,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
            options(nostack, preserves_flags)
        );
    }
    result & (1 << 0) != 0
}

pub fn enable_fsgsbase() {
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        let new_cr4 = cr4 | (1 << 16);
        asm!("mov cr4, {}", in(reg) new_cr4, options(nomem, nostack, preserves_flags));
    }
}

pub fn is_fsgsbase_enabled() -> bool {
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    cr4 & (1 << 16) != 0
}
