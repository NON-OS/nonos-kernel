// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for arch/x86_64/gdt

use crate::arch::x86_64::gdt::{
    GdtEntry, MAX_CPUS, TSS_SIZE, IST_COUNT, DEFAULT_STACK_SIZE,
    SEL_NULL, SEL_KERNEL_CODE, SEL_KERNEL_DATA, SEL_USER_CODE, SEL_USER_DATA, SEL_TSS,
    IST_DOUBLE_FAULT, IST_NMI, IST_MACHINE_CHECK, IST_DEBUG, IST_PAGE_FAULT, IST_GP,
};

#[test_case]
fn test_gdt_constants() {
    assert_eq!(MAX_CPUS, 256);
    assert_eq!(TSS_SIZE, 104);
    assert_eq!(IST_COUNT, 7);
    assert_eq!(DEFAULT_STACK_SIZE, 16384);
}

#[test_case]
fn test_segment_selectors() {
    assert_eq!(SEL_NULL, 0x00);
    assert_eq!(SEL_KERNEL_CODE, 0x08);
    assert_eq!(SEL_KERNEL_DATA, 0x10);
    assert_eq!(SEL_TSS, 0x28);
}

#[test_case]
fn test_user_selectors_have_ring3() {
    assert_eq!(SEL_USER_DATA & 0x03, 3);
    assert_eq!(SEL_USER_CODE & 0x03, 3);
}

#[test_case]
fn test_kernel_selectors_have_ring0() {
    assert_eq!(SEL_KERNEL_CODE & 0x03, 0);
    assert_eq!(SEL_KERNEL_DATA & 0x03, 0);
}

#[test_case]
fn test_ist_indices() {
    assert_eq!(IST_DOUBLE_FAULT, 1);
    assert_eq!(IST_NMI, 2);
    assert_eq!(IST_MACHINE_CHECK, 3);
    assert_eq!(IST_DEBUG, 4);
    assert_eq!(IST_PAGE_FAULT, 5);
    assert_eq!(IST_GP, 6);
}

#[test_case]
fn test_ist_indices_valid() {
    assert!(IST_DOUBLE_FAULT > 0 && IST_DOUBLE_FAULT <= IST_COUNT);
    assert!(IST_NMI > 0 && IST_NMI <= IST_COUNT);
    assert!(IST_MACHINE_CHECK > 0 && IST_MACHINE_CHECK <= IST_COUNT);
    assert!(IST_DEBUG > 0 && IST_DEBUG <= IST_COUNT);
    assert!(IST_PAGE_FAULT > 0 && IST_PAGE_FAULT <= IST_COUNT);
    assert!(IST_GP > 0 && IST_GP <= IST_COUNT);
}

#[test_case]
fn test_gdt_entry_null() {
    let entry = GdtEntry::null();
    assert_eq!(entry.limit_low, 0);
    assert_eq!(entry.base_low, 0);
    assert_eq!(entry.base_mid, 0);
    assert_eq!(entry.access, 0);
    assert_eq!(entry.granularity, 0);
    assert_eq!(entry.base_high, 0);
    assert!(!entry.is_present());
}

#[test_case]
fn test_gdt_entry_kernel_code() {
    let entry = GdtEntry::kernel_code_64();
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 0);
    assert!(entry.is_code());
    assert!(entry.is_long_mode());
}

#[test_case]
fn test_gdt_entry_kernel_data() {
    let entry = GdtEntry::kernel_data();
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 0);
    assert!(!entry.is_code());
}

#[test_case]
fn test_gdt_entry_user_code() {
    let entry = GdtEntry::user_code_64();
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 3);
    assert!(entry.is_code());
    assert!(entry.is_long_mode());
}

#[test_case]
fn test_gdt_entry_user_data() {
    let entry = GdtEntry::user_data();
    assert!(entry.is_present());
    assert_eq!(entry.dpl(), 3);
    assert!(!entry.is_code());
}

#[test_case]
fn test_gdt_entry_new() {
    let entry = GdtEntry::new(0x12345678, 0xABCDE, 0x9A, 0xCF);
    assert_eq!(entry.base_low, 0x5678);
    assert_eq!(entry.base_mid, 0x34);
    assert_eq!(entry.base_high, 0x12);
    assert_eq!(entry.limit_low, 0xBCDE);
    assert_eq!(entry.access, 0x9A);
}

#[test_case]
fn test_gdt_entry_clone() {
    let entry1 = GdtEntry::kernel_code_64();
    let entry2 = entry1.clone();
    assert_eq!(entry1.access, entry2.access);
    assert_eq!(entry1.granularity, entry2.granularity);
}

#[test_case]
fn test_gdt_entry_copy() {
    let entry1 = GdtEntry::kernel_data();
    let entry2 = entry1;
    assert_eq!(entry1.access, entry2.access);
}

#[test_case]
fn test_selector_alignment() {
    assert_eq!(SEL_NULL % 8, 0);
    assert_eq!((SEL_KERNEL_CODE & !0x03) % 8, 0);
    assert_eq!((SEL_KERNEL_DATA & !0x03) % 8, 0);
    assert_eq!((SEL_USER_CODE & !0x03) % 8, 0);
    assert_eq!((SEL_USER_DATA & !0x03) % 8, 0);
    assert_eq!((SEL_TSS & !0x03) % 8, 0);
}

#[test_case]
fn test_tss_size_valid() {
    assert!(TSS_SIZE >= 104);
}

#[test_case]
fn test_default_stack_size_aligned() {
    assert_eq!(DEFAULT_STACK_SIZE % 4096, 0);
}
