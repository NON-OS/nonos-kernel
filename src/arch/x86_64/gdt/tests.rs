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

use core::mem::size_of;
use super::*;

#[test]
fn test_error_messages() {
    assert_eq!(GdtError::None.as_str(), "no error");
    assert_eq!(GdtError::NotInitialized.as_str(), "GDT not initialized");
    assert_eq!(GdtError::InvalidIstIndex.as_str(), "IST index must be 1-7");
}

#[test]
fn test_selectors() {
    assert_eq!(SEL_NULL, 0x00);
    assert_eq!(SEL_KERNEL_CODE, 0x08);
    assert_eq!(SEL_KERNEL_DATA, 0x10);
    assert_eq!(SEL_USER_DATA, 0x1B);
    assert_eq!(SEL_USER_CODE, 0x23);
    assert_eq!(SEL_TSS, 0x28);
}

#[test]
fn test_gdt_entry_size() {
    assert_eq!(size_of::<GdtEntry>(), 8);
}

#[test]
fn test_tss_entry_size() {
    assert_eq!(size_of::<TssEntry>(), 16);
}

#[test]
fn test_tss_size() {
    assert_eq!(size_of::<Tss>(), TSS_SIZE);
}

#[test]
fn test_gdt_size() {
    assert_eq!(Gdt::size(), 56);
}

#[test]
fn test_gdt_entry_null() {
    let entry = GdtEntry::null();
    assert!(!entry.is_present());
    assert_eq!(entry.dpl(), 0);
}

#[test]
fn test_gdt_entry_kernel_code() {
    let entry = GdtEntry::kernel_code_64();
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 0);
    assert!(entry.is_code());
    assert!(entry.is_long_mode());
}

#[test]
fn test_gdt_entry_user_code() {
    let entry = GdtEntry::user_code_64();
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 3);
    assert!(entry.is_code());
    assert!(entry.is_long_mode());
}

#[test]
fn test_tss_new() {
    let tss = Tss::new();
    assert_eq!(tss.rsp0(), 0);
    let iomap = { tss.iomap_base };
    assert_eq!(iomap, TSS_SIZE as u16);
}

#[test]
fn test_tss_ist_bounds() {
    let mut tss = Tss::new();
    assert!(tss.set_ist(0, 0x1000).is_err());
    assert!(tss.set_ist(8, 0x1000).is_err());
    assert!(tss.set_ist(1, 0x1000).is_ok());
    assert!(tss.set_ist(7, 0x7000).is_ok());
    assert_eq!(tss.get_ist(1).unwrap(), 0x1000);
    assert_eq!(tss.get_ist(7).unwrap(), 0x7000);
}

#[test]
fn test_tss_rsp_bounds() {
    let mut tss = Tss::new();
    assert!(tss.set_rsp(3, 0x1000).is_err());
    assert!(tss.set_rsp(0, 0x1000).is_ok());
    assert!(tss.set_rsp(2, 0x3000).is_ok());
    assert_eq!(tss.get_rsp(0).unwrap(), 0x1000);
    assert_eq!(tss.get_rsp(2).unwrap(), 0x3000);
}

#[test]
fn test_syscall_selectors() {
    let sysret_base: u16 = 0x10;
    let syscall_base: u16 = 0x08;
    assert_eq!(syscall_base, SEL_KERNEL_CODE);
    assert_eq!(syscall_base + 8, SEL_KERNEL_DATA);
    assert_eq!((sysret_base + 16) | 3, SEL_USER_CODE);
    assert_eq!((sysret_base + 8) | 3, SEL_USER_DATA);
}

#[test]
fn test_selectors_struct() {
    let sels = Selectors::standard();
    assert_eq!(sels.kernel_code, SEL_KERNEL_CODE);
    assert_eq!(sels.kernel_data, SEL_KERNEL_DATA);
    assert_eq!(sels.user_code, SEL_USER_CODE);
    assert_eq!(sels.user_data, SEL_USER_DATA);
    assert_eq!(sels.tss, SEL_TSS);
}
