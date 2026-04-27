// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::arch::x86_64::boot::constants::*;
use crate::arch::x86_64::boot::stage::BootStage;
use crate::arch::x86_64::boot::types::{BootStats, ExceptionContext};
use crate::test::framework::TestResult;
use alloc::vec::Vec;

pub(crate) fn test_boot_stack_base() -> TestResult {
    if BOOT_STACK_BASE != 0x100000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stack_size() -> TestResult {
    if BOOT_STACK_SIZE != 0x10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stack_top() -> TestResult {
    if BOOT_STACK_TOP != BOOT_STACK_BASE + BOOT_STACK_SIZE - 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stack_alignment() -> TestResult {
    if BOOT_STACK_TOP % 16 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_efer() -> TestResult {
    if MSR_EFER != 0xC000_0080 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_star() -> TestResult {
    if MSR_STAR != 0xC000_0081 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_lstar() -> TestResult {
    if MSR_LSTAR != 0xC000_0082 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_sfmask() -> TestResult {
    if MSR_SFMASK != 0xC000_0084 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_fs_base() -> TestResult {
    if MSR_FS_BASE != 0xC000_0100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_gs_base() -> TestResult {
    if MSR_GS_BASE != 0xC000_0101 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_msr_kernel_gs_base() -> TestResult {
    if MSR_KERNEL_GS_BASE != 0xC000_0102 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_efer_sce() -> TestResult {
    if EFER_SCE != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_efer_lme() -> TestResult {
    if EFER_LME != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_efer_lma() -> TestResult {
    if EFER_LMA != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_efer_nxe() -> TestResult {
    if EFER_NXE != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_pe() -> TestResult {
    if CR0_PE != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_mp() -> TestResult {
    if CR0_MP != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_em() -> TestResult {
    if CR0_EM != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_ts() -> TestResult {
    if CR0_TS != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_et() -> TestResult {
    if CR0_ET != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_ne() -> TestResult {
    if CR0_NE != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_wp() -> TestResult {
    if CR0_WP != 1 << 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_am() -> TestResult {
    if CR0_AM != 1 << 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_nw() -> TestResult {
    if CR0_NW != 1 << 29 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_cd() -> TestResult {
    if CR0_CD != 1 << 30 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr0_pg() -> TestResult {
    if CR0_PG != 1 << 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_vme() -> TestResult {
    if CR4_VME != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_pvi() -> TestResult {
    if CR4_PVI != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_tsd() -> TestResult {
    if CR4_TSD != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_de() -> TestResult {
    if CR4_DE != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_pse() -> TestResult {
    if CR4_PSE != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_pae() -> TestResult {
    if CR4_PAE != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_mce() -> TestResult {
    if CR4_MCE != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_pge() -> TestResult {
    if CR4_PGE != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_pce() -> TestResult {
    if CR4_PCE != 1 << 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_osfxsr() -> TestResult {
    if CR4_OSFXSR != 1 << 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_osxmmexcpt() -> TestResult {
    if CR4_OSXMMEXCPT != 1 << 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_umip() -> TestResult {
    if CR4_UMIP != 1 << 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_fsgsbase() -> TestResult {
    if CR4_FSGSBASE != 1 << 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_pcide() -> TestResult {
    if CR4_PCIDE != 1 << 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_osxsave() -> TestResult {
    if CR4_OSXSAVE != 1 << 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_smep() -> TestResult {
    if CR4_SMEP != 1 << 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cr4_smap() -> TestResult {
    if CR4_SMAP != 1 << 21 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_x87() -> TestResult {
    if XCR0_X87 != 1 << 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_sse() -> TestResult {
    if XCR0_SSE != 1 << 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_avx() -> TestResult {
    if XCR0_AVX != 1 << 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_bndreg() -> TestResult {
    if XCR0_BNDREG != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_bndcsr() -> TestResult {
    if XCR0_BNDCSR != 1 << 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_opmask() -> TestResult {
    if XCR0_OPMASK != 1 << 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_zmm_hi256() -> TestResult {
    if XCR0_ZMM_HI256 != 1 << 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_hi16_zmm() -> TestResult {
    if XCR0_HI16_ZMM != 1 << 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_xcr0_combined() -> TestResult {
    if XCR0_X87 | XCR0_SSE | XCR0_AVX != 0x07 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_count() -> TestResult {
    if BOOT_STAGE_COUNT != 11 {
        return TestResult::Fail;
    }
    if BootStage::COUNT != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_entry() -> TestResult {
    if BootStage::Entry as u8 != 0 {
        return TestResult::Fail;
    }
    if BootStage::Entry.as_str() != "Entry" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_serial_init() -> TestResult {
    if BootStage::SerialInit as u8 != 1 {
        return TestResult::Fail;
    }
    if BootStage::SerialInit.as_str() != "Serial Init" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_vga_init() -> TestResult {
    if BootStage::VgaInit as u8 != 2 {
        return TestResult::Fail;
    }
    if BootStage::VgaInit.as_str() != "VGA Init" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_cpu_detect() -> TestResult {
    if BootStage::CpuDetect as u8 != 3 {
        return TestResult::Fail;
    }
    if BootStage::CpuDetect.as_str() != "CPU Detection" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_gdt_setup() -> TestResult {
    if BootStage::GdtSetup as u8 != 4 {
        return TestResult::Fail;
    }
    if BootStage::GdtSetup.as_str() != "GDT/TSS Setup" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_segment_reload() -> TestResult {
    if BootStage::SegmentReload as u8 != 5 {
        return TestResult::Fail;
    }
    if BootStage::SegmentReload.as_str() != "Segment Reload" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_sse_enable() -> TestResult {
    if BootStage::SseEnable as u8 != 6 {
        return TestResult::Fail;
    }
    if BootStage::SseEnable.as_str() != "SSE/AVX Enable" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_idt_setup() -> TestResult {
    if BootStage::IdtSetup as u8 != 7 {
        return TestResult::Fail;
    }
    if BootStage::IdtSetup.as_str() != "IDT Setup" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_memory_validation() -> TestResult {
    if BootStage::MemoryValidation as u8 != 8 {
        return TestResult::Fail;
    }
    if BootStage::MemoryValidation.as_str() != "Memory Validation" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_kernel_transfer() -> TestResult {
    if BootStage::KernelTransfer as u8 != 9 {
        return TestResult::Fail;
    }
    if BootStage::KernelTransfer.as_str() != "Kernel Transfer" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_complete() -> TestResult {
    if BootStage::Complete as u8 != 10 {
        return TestResult::Fail;
    }
    if BootStage::Complete.as_str() != "Complete" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_from_u8() -> TestResult {
    if BootStage::from_u8(0) != BootStage::Entry {
        return TestResult::Fail;
    }
    if BootStage::from_u8(5) != BootStage::SegmentReload {
        return TestResult::Fail;
    }
    if BootStage::from_u8(10) != BootStage::Complete {
        return TestResult::Fail;
    }
    if BootStage::from_u8(100) != BootStage::Complete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_as_u8() -> TestResult {
    if BootStage::Entry.as_u8() != 0 {
        return TestResult::Fail;
    }
    if BootStage::Complete.as_u8() != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_next() -> TestResult {
    if BootStage::Entry.next() != Some(BootStage::SerialInit) {
        return TestResult::Fail;
    }
    if BootStage::SerialInit.next() != Some(BootStage::VgaInit) {
        return TestResult::Fail;
    }
    if BootStage::KernelTransfer.next() != Some(BootStage::Complete) {
        return TestResult::Fail;
    }
    if BootStage::Complete.next() != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_prev() -> TestResult {
    if BootStage::Entry.prev() != None {
        return TestResult::Fail;
    }
    if BootStage::SerialInit.prev() != Some(BootStage::Entry) {
        return TestResult::Fail;
    }
    if BootStage::Complete.prev() != Some(BootStage::KernelTransfer) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_is_complete() -> TestResult {
    if BootStage::Entry.is_complete() {
        return TestResult::Fail;
    }
    if BootStage::KernelTransfer.is_complete() {
        return TestResult::Fail;
    }
    if !BootStage::Complete.is_complete() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_is_early() -> TestResult {
    if !BootStage::Entry.is_early() {
        return TestResult::Fail;
    }
    if !BootStage::SerialInit.is_early() {
        return TestResult::Fail;
    }
    if !BootStage::VgaInit.is_early() {
        return TestResult::Fail;
    }
    if !BootStage::CpuDetect.is_early() {
        return TestResult::Fail;
    }
    if BootStage::GdtSetup.is_early() {
        return TestResult::Fail;
    }
    if BootStage::Complete.is_early() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_has_interrupts() -> TestResult {
    if BootStage::Entry.has_interrupts() {
        return TestResult::Fail;
    }
    if BootStage::GdtSetup.has_interrupts() {
        return TestResult::Fail;
    }
    if !BootStage::IdtSetup.has_interrupts() {
        return TestResult::Fail;
    }
    if !BootStage::MemoryValidation.has_interrupts() {
        return TestResult::Fail;
    }
    if !BootStage::KernelTransfer.has_interrupts() {
        return TestResult::Fail;
    }
    if !BootStage::Complete.has_interrupts() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_all() -> TestResult {
    let stages: Vec<BootStage> = BootStage::all().collect();
    if stages.len() != BootStage::COUNT {
        return TestResult::Fail;
    }
    if stages[0] != BootStage::Entry {
        return TestResult::Fail;
    }
    if stages[10] != BootStage::Complete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_ordering() -> TestResult {
    if BootStage::Entry >= BootStage::SerialInit {
        return TestResult::Fail;
    }
    if BootStage::SerialInit >= BootStage::Complete {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stage_default() -> TestResult {
    if BootStage::default() != BootStage::Entry {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_default() -> TestResult {
    let ctx = ExceptionContext::default();
    if ctx.rip != 0 {
        return TestResult::Fail;
    }
    if ctx.rsp != 0 {
        return TestResult::Fail;
    }
    if ctx.rax != 0 {
        return TestResult::Fail;
    }
    if ctx.vector != 0 {
        return TestResult::Fail;
    }
    if ctx.error_code != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_instruction_pointer() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.rip = 0x1234;
    if ctx.instruction_pointer() != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_stack_pointer() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.rsp = 0x5678;
    if ctx.stack_pointer() != 0x5678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_code_segment() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.cs = 0x08;
    if ctx.code_segment() != 0x08 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_is_user_mode() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.cs = 0x08;
    if ctx.is_user_mode() {
        return TestResult::Fail;
    }
    ctx.cs = 0x1B;
    if !ctx.is_user_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_is_kernel_mode() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.cs = 0x08;
    if !ctx.is_kernel_mode() {
        return TestResult::Fail;
    }
    ctx.cs = 0x1B;
    if ctx.is_kernel_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_has_error_code() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.vector = 8;
    if !ctx.has_error_code() {
        return TestResult::Fail;
    }
    ctx.vector = 14;
    if !ctx.has_error_code() {
        return TestResult::Fail;
    }
    ctx.vector = 13;
    if !ctx.has_error_code() {
        return TestResult::Fail;
    }
    ctx.vector = 0;
    if ctx.has_error_code() {
        return TestResult::Fail;
    }
    ctx.vector = 6;
    if ctx.has_error_code() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_default() -> TestResult {
    let stats = BootStats::default();
    if stats.stage != 0 {
        return TestResult::Fail;
    }
    if stats.error != 0 {
        return TestResult::Fail;
    }
    if stats.complete {
        return TestResult::Fail;
    }
    if stats.boot_tsc != 0 {
        return TestResult::Fail;
    }
    if stats.complete_tsc != 0 {
        return TestResult::Fail;
    }
    if stats.exceptions != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_duration_tsc() -> TestResult {
    let stats = BootStats { boot_tsc: 1000, complete_tsc: 5000, ..Default::default() };
    if stats.duration_tsc() != 4000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_duration_tsc_zero() -> TestResult {
    let stats = BootStats::default();
    if stats.duration_tsc() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_current_stage() -> TestResult {
    let mut stats = BootStats::default();
    stats.stage = 5;
    if stats.current_stage() != BootStage::SegmentReload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_is_complete() -> TestResult {
    let mut stats = BootStats::default();
    if stats.is_complete() {
        return TestResult::Fail;
    }
    stats.complete = true;
    if !stats.is_complete() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_has_error() -> TestResult {
    let mut stats = BootStats::default();
    if stats.has_error() {
        return TestResult::Fail;
    }
    stats.error = 1;
    if !stats.has_error() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_copy() -> TestResult {
    let ctx = ExceptionContext::default();
    let copy = ctx;
    if copy.rip != ctx.rip {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_context_clone() -> TestResult {
    let mut ctx = ExceptionContext::default();
    ctx.rax = 42;
    let cloned = ctx.clone();
    if cloned.rax != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_boot_stats_copy() -> TestResult {
    let stats = BootStats::default();
    let copy = stats;
    if copy.stage != stats.stage {
        return TestResult::Fail;
    }
    TestResult::Pass
}
