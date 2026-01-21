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

pub const BOOT_STACK_BASE: u64 = 0x100000;
pub const BOOT_STACK_SIZE: u64 = 0x10000;
pub const BOOT_STACK_TOP: u64 = BOOT_STACK_BASE + BOOT_STACK_SIZE - 16;
pub const MSR_EFER: u32 = 0xC000_0080;
pub const MSR_STAR: u32 = 0xC000_0081;
pub const MSR_LSTAR: u32 = 0xC000_0082;
pub const MSR_SFMASK: u32 = 0xC000_0084;
pub const MSR_FS_BASE: u32 = 0xC000_0100;
pub const MSR_GS_BASE: u32 = 0xC000_0101;
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
pub const EFER_SCE: u64 = 1 << 0;
pub const EFER_LME: u64 = 1 << 8;
pub const EFER_LMA: u64 = 1 << 10;
pub const EFER_NXE: u64 = 1 << 11;
pub const CR0_PE: u64 = 1 << 0;
pub const CR0_MP: u64 = 1 << 1;
pub const CR0_EM: u64 = 1 << 2;
pub const CR0_TS: u64 = 1 << 3;
pub const CR0_ET: u64 = 1 << 4;
pub const CR0_NE: u64 = 1 << 5;
pub const CR0_WP: u64 = 1 << 16;
pub const CR0_AM: u64 = 1 << 18;
pub const CR0_NW: u64 = 1 << 29;
pub const CR0_CD: u64 = 1 << 30;
pub const CR0_PG: u64 = 1 << 31;
pub const CR4_VME: u64 = 1 << 0;
pub const CR4_PVI: u64 = 1 << 1;
pub const CR4_TSD: u64 = 1 << 2;
pub const CR4_DE: u64 = 1 << 3;
pub const CR4_PSE: u64 = 1 << 4;
pub const CR4_PAE: u64 = 1 << 5;
pub const CR4_MCE: u64 = 1 << 6;
pub const CR4_PGE: u64 = 1 << 7;
pub const CR4_PCE: u64 = 1 << 8;
pub const CR4_OSFXSR: u64 = 1 << 9;
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;
pub const CR4_UMIP: u64 = 1 << 11;
pub const CR4_FSGSBASE: u64 = 1 << 16;
pub const CR4_PCIDE: u64 = 1 << 17;
pub const CR4_OSXSAVE: u64 = 1 << 18;
pub const CR4_SMEP: u64 = 1 << 20;
pub const CR4_SMAP: u64 = 1 << 21;
pub const XCR0_X87: u64 = 1 << 0;
pub const XCR0_SSE: u64 = 1 << 1;
pub const XCR0_AVX: u64 = 1 << 2;
pub const XCR0_BNDREG: u64 = 1 << 3;
pub const XCR0_BNDCSR: u64 = 1 << 4;
pub const XCR0_OPMASK: u64 = 1 << 5;
pub const XCR0_ZMM_HI256: u64 = 1 << 6;
pub const XCR0_HI16_ZMM: u64 = 1 << 7;
pub const KERNEL_CS: u16 = crate::arch::x86_64::gdt::SEL_KERNEL_CODE;
pub const KERNEL_DS: u16 = crate::arch::x86_64::gdt::SEL_KERNEL_DATA;
pub const USER_CS: u16 = crate::arch::x86_64::gdt::SEL_USER_CODE;
pub const USER_DS: u16 = crate::arch::x86_64::gdt::SEL_USER_DATA;
pub const TSS_SEL: u16 = crate::arch::x86_64::gdt::SEL_TSS;
pub const BOOT_STAGE_COUNT: usize = 11;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_stack_alignment() {
        assert_eq!(BOOT_STACK_TOP % 16, 0);
    }

    #[test]
    fn test_cr_flags() {
        assert_eq!(CR0_PG, 0x80000000);
        assert_eq!(CR4_PAE, 0x20);
    }

    #[test]
    fn test_xcr0_flags() {
        assert_eq!(XCR0_X87 | XCR0_SSE | XCR0_AVX, 0x07);
    }
}
