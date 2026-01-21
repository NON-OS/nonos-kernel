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

pub const IA32_EFER: u32 = 0xC0000080;
pub const IA32_STAR: u32 = 0xC0000081;
pub const IA32_LSTAR: u32 = 0xC0000082;
pub const IA32_CSTAR: u32 = 0xC0000083;
pub const IA32_FMASK: u32 = 0xC0000084;
pub const IA32_FS_BASE: u32 = 0xC0000100;
pub const IA32_GS_BASE: u32 = 0xC0000101;
pub const IA32_KERNEL_GS_BASE: u32 = 0xC0000102;
pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;
pub const RFLAGS_IF: u64 = 1 << 9;
pub const RFLAGS_TF: u64 = 1 << 8;
pub const RFLAGS_DF: u64 = 1 << 10;
pub const RFLAGS_AC: u64 = 1 << 18;

#[inline]
pub fn read_msr(msr_addr: u32) -> u64 {
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr_addr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

#[inline]
pub fn write_msr(msr_addr: u32, value: u64) {
    unsafe {
        let lo = value as u32;
        let hi = (value >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr_addr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags)
        );
    }
}

pub fn setup_star(kernel_cs: u16, _kernel_ss: u16, user_cs: u16, _user_ss: u16) {
    let syscall_sel = (kernel_cs as u64) << 32;
    let sysret_sel = ((user_cs as u64) - 16) << 48;
    let star_value = syscall_sel | sysret_sel;
    write_msr(IA32_STAR, star_value);
}

pub fn setup_lstar(entry_point: u64) {
    write_msr(IA32_LSTAR, entry_point);
}

pub fn setup_fmask() {
    let mask = RFLAGS_IF | RFLAGS_TF | RFLAGS_DF | RFLAGS_AC;
    write_msr(IA32_FMASK, mask);
}

pub fn enable_sce() {
    let mut efer = read_msr(IA32_EFER);
    efer |= EFER_SCE;
    write_msr(IA32_EFER, efer);
}

pub fn is_sce_enabled() -> bool {
    let efer = read_msr(IA32_EFER);
    (efer & EFER_SCE) != 0
}
