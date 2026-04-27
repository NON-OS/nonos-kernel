// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::x86_64::gdt::{
    GdtEntry, DEFAULT_STACK_SIZE, IST_COUNT, IST_DEBUG, IST_DOUBLE_FAULT, IST_GP,
    IST_MACHINE_CHECK, IST_NMI, IST_PAGE_FAULT, MAX_CPUS, SEL_KERNEL_CODE, SEL_KERNEL_DATA,
    SEL_NULL, SEL_TSS, SEL_USER_CODE, SEL_USER_DATA, TSS_SIZE,
};
use crate::test::framework::TestResult;

pub(crate) fn test_gdt_constants() -> TestResult {
    if MAX_CPUS != 256 {
        return TestResult::Fail;
    }
    if TSS_SIZE != 104 {
        return TestResult::Fail;
    }
    if IST_COUNT != 7 {
        return TestResult::Fail;
    }
    if DEFAULT_STACK_SIZE != 16384 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_segment_selectors() -> TestResult {
    if SEL_NULL != 0x00 {
        return TestResult::Fail;
    }
    if SEL_KERNEL_CODE != 0x08 {
        return TestResult::Fail;
    }
    if SEL_KERNEL_DATA != 0x10 {
        return TestResult::Fail;
    }
    if SEL_TSS != 0x28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_user_selectors_have_ring3() -> TestResult {
    if SEL_USER_DATA & 0x03 != 3 {
        return TestResult::Fail;
    }
    if SEL_USER_CODE & 0x03 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_kernel_selectors_have_ring0() -> TestResult {
    if SEL_KERNEL_CODE & 0x03 != 0 {
        return TestResult::Fail;
    }
    if SEL_KERNEL_DATA & 0x03 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ist_indices() -> TestResult {
    if IST_DOUBLE_FAULT != 1 {
        return TestResult::Fail;
    }
    if IST_NMI != 2 {
        return TestResult::Fail;
    }
    if IST_MACHINE_CHECK != 3 {
        return TestResult::Fail;
    }
    if IST_DEBUG != 4 {
        return TestResult::Fail;
    }
    if IST_PAGE_FAULT != 5 {
        return TestResult::Fail;
    }
    if IST_GP != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ist_indices_valid() -> TestResult {
    if IST_DOUBLE_FAULT == 0 || IST_DOUBLE_FAULT > IST_COUNT {
        return TestResult::Fail;
    }
    if IST_NMI == 0 || IST_NMI > IST_COUNT {
        return TestResult::Fail;
    }
    if IST_MACHINE_CHECK == 0 || IST_MACHINE_CHECK > IST_COUNT {
        return TestResult::Fail;
    }
    if IST_DEBUG == 0 || IST_DEBUG > IST_COUNT {
        return TestResult::Fail;
    }
    if IST_PAGE_FAULT == 0 || IST_PAGE_FAULT > IST_COUNT {
        return TestResult::Fail;
    }
    if IST_GP == 0 || IST_GP > IST_COUNT {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_null() -> TestResult {
    let entry = GdtEntry::null();
    if entry.limit_low != 0 {
        return TestResult::Fail;
    }
    if entry.base_low != 0 {
        return TestResult::Fail;
    }
    if entry.base_mid != 0 {
        return TestResult::Fail;
    }
    if entry.access != 0 {
        return TestResult::Fail;
    }
    if entry.granularity != 0 {
        return TestResult::Fail;
    }
    if entry.base_high != 0 {
        return TestResult::Fail;
    }
    if entry.is_present() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_kernel_code() -> TestResult {
    let entry = GdtEntry::kernel_code_64();
    if !entry.is_present() {
        return TestResult::Fail;
    }
    if entry.dpl() != 0 {
        return TestResult::Fail;
    }
    if !entry.is_code() {
        return TestResult::Fail;
    }
    if !entry.is_long_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_kernel_data() -> TestResult {
    let entry = GdtEntry::kernel_data();
    if !entry.is_present() {
        return TestResult::Fail;
    }
    if entry.dpl() != 0 {
        return TestResult::Fail;
    }
    if entry.is_code() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_user_code() -> TestResult {
    let entry = GdtEntry::user_code_64();
    if !entry.is_present() {
        return TestResult::Fail;
    }
    if entry.dpl() != 3 {
        return TestResult::Fail;
    }
    if !entry.is_code() {
        return TestResult::Fail;
    }
    if !entry.is_long_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_user_data() -> TestResult {
    let entry = GdtEntry::user_data();
    if !entry.is_present() {
        return TestResult::Fail;
    }
    if entry.dpl() != 3 {
        return TestResult::Fail;
    }
    if entry.is_code() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_new() -> TestResult {
    let entry = GdtEntry::new(0x12345678, 0xABCDE, 0x9A, 0xCF);
    if entry.base_low != 0x5678 {
        return TestResult::Fail;
    }
    if entry.base_mid != 0x34 {
        return TestResult::Fail;
    }
    if entry.base_high != 0x12 {
        return TestResult::Fail;
    }
    if entry.limit_low != 0xBCDE {
        return TestResult::Fail;
    }
    if entry.access != 0x9A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_clone() -> TestResult {
    let entry1 = GdtEntry::kernel_code_64();
    let entry2 = entry1.clone();
    if entry1.access != entry2.access {
        return TestResult::Fail;
    }
    if entry1.granularity != entry2.granularity {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gdt_entry_copy() -> TestResult {
    let entry1 = GdtEntry::kernel_data();
    let entry2 = entry1;
    if entry1.access != entry2.access {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_selector_alignment() -> TestResult {
    if SEL_NULL % 8 != 0 {
        return TestResult::Fail;
    }
    if (SEL_KERNEL_CODE & !0x03) % 8 != 0 {
        return TestResult::Fail;
    }
    if (SEL_KERNEL_DATA & !0x03) % 8 != 0 {
        return TestResult::Fail;
    }
    if (SEL_USER_CODE & !0x03) % 8 != 0 {
        return TestResult::Fail;
    }
    if (SEL_USER_DATA & !0x03) % 8 != 0 {
        return TestResult::Fail;
    }
    if (SEL_TSS & !0x03) % 8 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tss_size_valid() -> TestResult {
    if TSS_SIZE < 104 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_stack_size_aligned() -> TestResult {
    if DEFAULT_STACK_SIZE % 4096 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
