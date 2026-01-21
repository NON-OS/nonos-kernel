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

#[inline]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: rdtsc is always available on x86_64
    unsafe {
        asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
pub fn rdtscp() -> (u64, u32) {
    let lo: u32;
    let hi: u32;
    let aux: u32;
    // SAFETY: rdtscp serializes and reads TSC
    unsafe {
        asm!(
            "rdtscp",
            out("eax") lo,
            out("edx") hi,
            out("ecx") aux,
            options(nomem, nostack, preserves_flags)
        );
    }
    (((hi as u64) << 32) | (lo as u64), aux)
}

#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Caller ensures MSR exists and is readable
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
pub unsafe fn wrmsr(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: Caller ensures MSR exists and value is valid
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr0() -> u64 {
    let value: u64;
    // SAFETY: Reading CR0 is always valid
    unsafe {
        asm!(
            "mov {}, cr0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr0(value: u64) {
    // SAFETY: Caller ensures CR0 value is valid
    asm!(
        "mov cr0, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr2() -> u64 {
    let value: u64;
    // SAFETY: Reading CR2 is always valid
    unsafe {
        asm!(
            "mov {}, cr2",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: Reading CR3 is always valid
    unsafe {
        asm!(
            "mov {}, cr3",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr3(value: u64) {
    // SAFETY: Caller ensures page table address is valid
    asm!(
        "mov cr3, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr4() -> u64 {
    let value: u64;
    // SAFETY: Reading CR4 is always valid
    unsafe {
        asm!(
            "mov {}, cr4",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr4(value: u64) {
    // SAFETY: Caller ensures CR4 value is valid
    asm!(
        "mov cr4, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub fn read_cr8() -> u64 {
    let value: u64;
    // SAFETY: Reading CR8 is always valid in long mode
    unsafe {
        asm!(
            "mov {}, cr8",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        );
    }
    value
}

#[inline]
pub unsafe fn write_cr8(value: u64) {
    // SAFETY: Caller ensures TPR value is valid
    asm!(
        "mov cr8, {}",
        in(reg) value,
        options(nomem, nostack, preserves_flags)
    );
}

#[inline]
pub unsafe fn write_xcr0(value: u64) {
    // SAFETY: Caller ensures XCR0 value is valid and OSXSAVE is set
    asm!(
        "xor ecx, ecx",
        "xsetbv",
        in("eax") value as u32,
        in("edx") (value >> 32) as u32,
        out("ecx") _,
        options(nomem, nostack)
    );
}

#[inline]
pub fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Reading XCR0 requires OSXSAVE in CR4
    unsafe {
        asm!(
            "xor ecx, ecx",
            "xgetbv",
            out("eax") lo,
            out("edx") hi,
            out("ecx") _,
            options(nomem, nostack)
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
pub fn read_rflags() -> u64 {
    let flags: u64;
    // SAFETY: pushfq/popfq are always valid
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, preserves_flags)
        );
    }
    flags
}

#[inline]
pub unsafe fn write_rflags(flags: u64) {
    // SAFETY: Caller ensures flags value is valid
    asm!(
        "push {}",
        "popfq",
        in(reg) flags,
        options(nomem)
    );
}

#[inline]
pub fn cli() {
    // SAFETY: Disabling interrupts is always valid
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn sti() {
    // SAFETY: Enabling interrupts is always valid
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn hlt() {
    // SAFETY: hlt is always valid
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn pause() {
    // SAFETY: pause is always valid
    unsafe {
        asm!("pause", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn lfence() {
    // SAFETY: lfence is always valid on x86_64
    unsafe {
        asm!("lfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn mfence() {
    // SAFETY: mfence is always valid on x86_64
    unsafe {
        asm!("mfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn sfence() {
    // SAFETY: sfence is always valid on x86_64
    unsafe {
        asm!("sfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline]
pub fn invlpg(addr: u64) {
    // SAFETY: invlpg with a valid address is safe
    unsafe {
        asm!(
            "invlpg [{}]",
            in(reg) addr,
            options(nostack, preserves_flags)
        );
    }
}

#[inline]
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is always valid on x86_64
    unsafe {
        asm!(
            "cpuid",
            inout("eax") leaf => eax,
            lateout("ebx") ebx,
            lateout("ecx") ecx,
            lateout("edx") edx,
            options(nomem, nostack, preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

#[inline]
pub fn cpuid_count(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: CPUID is always valid on x86_64
    unsafe {
        asm!(
            "cpuid",
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            lateout("ebx") ebx,
            lateout("edx") edx,
            options(nomem, nostack, preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

pub fn halt_loop() -> ! {
    loop {
        cli();
        hlt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdtsc_monotonic() {
        let t1 = rdtsc();
        let t2 = rdtsc();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_cpuid() {
        let (eax, _, _, _) = cpuid(0);
        assert!(eax >= 1);
    }

    #[test]
    fn test_read_cr0() {
        let cr0 = read_cr0();
        assert!(cr0 & 1 != 0);
    }

    #[test]
    fn test_read_cr3() {
        let cr3 = read_cr3();
        assert!(cr3 != 0);
    }

    #[test]
    fn test_read_cr4() {
        let cr4 = read_cr4();
        assert!(cr4 & (1 << 5) != 0);
    }
}
