extern crate alloc;

use alloc::vec::Vec;
use crate::arch::x86_64::boot::constants::*;
use crate::arch::x86_64::boot::stage::BootStage;
use crate::arch::x86_64::boot::types::{ExceptionContext, BootStats};

#[test]
fn test_boot_stack_base() {
    assert_eq!(BOOT_STACK_BASE, 0x100000);
}

#[test]
fn test_boot_stack_size() {
    assert_eq!(BOOT_STACK_SIZE, 0x10000);
}

#[test]
fn test_boot_stack_top() {
    assert_eq!(BOOT_STACK_TOP, BOOT_STACK_BASE + BOOT_STACK_SIZE - 16);
}

#[test]
fn test_boot_stack_alignment() {
    assert_eq!(BOOT_STACK_TOP % 16, 0);
}

#[test]
fn test_msr_efer() {
    assert_eq!(MSR_EFER, 0xC000_0080);
}

#[test]
fn test_msr_star() {
    assert_eq!(MSR_STAR, 0xC000_0081);
}

#[test]
fn test_msr_lstar() {
    assert_eq!(MSR_LSTAR, 0xC000_0082);
}

#[test]
fn test_msr_sfmask() {
    assert_eq!(MSR_SFMASK, 0xC000_0084);
}

#[test]
fn test_msr_fs_base() {
    assert_eq!(MSR_FS_BASE, 0xC000_0100);
}

#[test]
fn test_msr_gs_base() {
    assert_eq!(MSR_GS_BASE, 0xC000_0101);
}

#[test]
fn test_msr_kernel_gs_base() {
    assert_eq!(MSR_KERNEL_GS_BASE, 0xC000_0102);
}

#[test]
fn test_efer_sce() {
    assert_eq!(EFER_SCE, 1 << 0);
}

#[test]
fn test_efer_lme() {
    assert_eq!(EFER_LME, 1 << 8);
}

#[test]
fn test_efer_lma() {
    assert_eq!(EFER_LMA, 1 << 10);
}

#[test]
fn test_efer_nxe() {
    assert_eq!(EFER_NXE, 1 << 11);
}

#[test]
fn test_cr0_pe() {
    assert_eq!(CR0_PE, 1 << 0);
}

#[test]
fn test_cr0_mp() {
    assert_eq!(CR0_MP, 1 << 1);
}

#[test]
fn test_cr0_em() {
    assert_eq!(CR0_EM, 1 << 2);
}

#[test]
fn test_cr0_ts() {
    assert_eq!(CR0_TS, 1 << 3);
}

#[test]
fn test_cr0_et() {
    assert_eq!(CR0_ET, 1 << 4);
}

#[test]
fn test_cr0_ne() {
    assert_eq!(CR0_NE, 1 << 5);
}

#[test]
fn test_cr0_wp() {
    assert_eq!(CR0_WP, 1 << 16);
}

#[test]
fn test_cr0_am() {
    assert_eq!(CR0_AM, 1 << 18);
}

#[test]
fn test_cr0_nw() {
    assert_eq!(CR0_NW, 1 << 29);
}

#[test]
fn test_cr0_cd() {
    assert_eq!(CR0_CD, 1 << 30);
}

#[test]
fn test_cr0_pg() {
    assert_eq!(CR0_PG, 1 << 31);
}

#[test]
fn test_cr4_vme() {
    assert_eq!(CR4_VME, 1 << 0);
}

#[test]
fn test_cr4_pvi() {
    assert_eq!(CR4_PVI, 1 << 1);
}

#[test]
fn test_cr4_tsd() {
    assert_eq!(CR4_TSD, 1 << 2);
}

#[test]
fn test_cr4_de() {
    assert_eq!(CR4_DE, 1 << 3);
}

#[test]
fn test_cr4_pse() {
    assert_eq!(CR4_PSE, 1 << 4);
}

#[test]
fn test_cr4_pae() {
    assert_eq!(CR4_PAE, 1 << 5);
}

#[test]
fn test_cr4_mce() {
    assert_eq!(CR4_MCE, 1 << 6);
}

#[test]
fn test_cr4_pge() {
    assert_eq!(CR4_PGE, 1 << 7);
}

#[test]
fn test_cr4_pce() {
    assert_eq!(CR4_PCE, 1 << 8);
}

#[test]
fn test_cr4_osfxsr() {
    assert_eq!(CR4_OSFXSR, 1 << 9);
}

#[test]
fn test_cr4_osxmmexcpt() {
    assert_eq!(CR4_OSXMMEXCPT, 1 << 10);
}

#[test]
fn test_cr4_umip() {
    assert_eq!(CR4_UMIP, 1 << 11);
}

#[test]
fn test_cr4_fsgsbase() {
    assert_eq!(CR4_FSGSBASE, 1 << 16);
}

#[test]
fn test_cr4_pcide() {
    assert_eq!(CR4_PCIDE, 1 << 17);
}

#[test]
fn test_cr4_osxsave() {
    assert_eq!(CR4_OSXSAVE, 1 << 18);
}

#[test]
fn test_cr4_smep() {
    assert_eq!(CR4_SMEP, 1 << 20);
}

#[test]
fn test_cr4_smap() {
    assert_eq!(CR4_SMAP, 1 << 21);
}

#[test]
fn test_xcr0_x87() {
    assert_eq!(XCR0_X87, 1 << 0);
}

#[test]
fn test_xcr0_sse() {
    assert_eq!(XCR0_SSE, 1 << 1);
}

#[test]
fn test_xcr0_avx() {
    assert_eq!(XCR0_AVX, 1 << 2);
}

#[test]
fn test_xcr0_bndreg() {
    assert_eq!(XCR0_BNDREG, 1 << 3);
}

#[test]
fn test_xcr0_bndcsr() {
    assert_eq!(XCR0_BNDCSR, 1 << 4);
}

#[test]
fn test_xcr0_opmask() {
    assert_eq!(XCR0_OPMASK, 1 << 5);
}

#[test]
fn test_xcr0_zmm_hi256() {
    assert_eq!(XCR0_ZMM_HI256, 1 << 6);
}

#[test]
fn test_xcr0_hi16_zmm() {
    assert_eq!(XCR0_HI16_ZMM, 1 << 7);
}

#[test]
fn test_xcr0_combined() {
    assert_eq!(XCR0_X87 | XCR0_SSE | XCR0_AVX, 0x07);
}

#[test]
fn test_boot_stage_count() {
    assert_eq!(BOOT_STAGE_COUNT, 11);
    assert_eq!(BootStage::COUNT, 11);
}

#[test]
fn test_boot_stage_entry() {
    assert_eq!(BootStage::Entry as u8, 0);
    assert_eq!(BootStage::Entry.as_str(), "Entry");
}

#[test]
fn test_boot_stage_serial_init() {
    assert_eq!(BootStage::SerialInit as u8, 1);
    assert_eq!(BootStage::SerialInit.as_str(), "Serial Init");
}

#[test]
fn test_boot_stage_vga_init() {
    assert_eq!(BootStage::VgaInit as u8, 2);
    assert_eq!(BootStage::VgaInit.as_str(), "VGA Init");
}

#[test]
fn test_boot_stage_cpu_detect() {
    assert_eq!(BootStage::CpuDetect as u8, 3);
    assert_eq!(BootStage::CpuDetect.as_str(), "CPU Detection");
}

#[test]
fn test_boot_stage_gdt_setup() {
    assert_eq!(BootStage::GdtSetup as u8, 4);
    assert_eq!(BootStage::GdtSetup.as_str(), "GDT/TSS Setup");
}

#[test]
fn test_boot_stage_segment_reload() {
    assert_eq!(BootStage::SegmentReload as u8, 5);
    assert_eq!(BootStage::SegmentReload.as_str(), "Segment Reload");
}

#[test]
fn test_boot_stage_sse_enable() {
    assert_eq!(BootStage::SseEnable as u8, 6);
    assert_eq!(BootStage::SseEnable.as_str(), "SSE/AVX Enable");
}

#[test]
fn test_boot_stage_idt_setup() {
    assert_eq!(BootStage::IdtSetup as u8, 7);
    assert_eq!(BootStage::IdtSetup.as_str(), "IDT Setup");
}

#[test]
fn test_boot_stage_memory_validation() {
    assert_eq!(BootStage::MemoryValidation as u8, 8);
    assert_eq!(BootStage::MemoryValidation.as_str(), "Memory Validation");
}

#[test]
fn test_boot_stage_kernel_transfer() {
    assert_eq!(BootStage::KernelTransfer as u8, 9);
    assert_eq!(BootStage::KernelTransfer.as_str(), "Kernel Transfer");
}

#[test]
fn test_boot_stage_complete() {
    assert_eq!(BootStage::Complete as u8, 10);
    assert_eq!(BootStage::Complete.as_str(), "Complete");
}

#[test]
fn test_boot_stage_from_u8() {
    assert_eq!(BootStage::from_u8(0), BootStage::Entry);
    assert_eq!(BootStage::from_u8(5), BootStage::SegmentReload);
    assert_eq!(BootStage::from_u8(10), BootStage::Complete);
    assert_eq!(BootStage::from_u8(100), BootStage::Complete);
}

#[test]
fn test_boot_stage_as_u8() {
    assert_eq!(BootStage::Entry.as_u8(), 0);
    assert_eq!(BootStage::Complete.as_u8(), 10);
}

#[test]
fn test_boot_stage_next() {
    assert_eq!(BootStage::Entry.next(), Some(BootStage::SerialInit));
    assert_eq!(BootStage::SerialInit.next(), Some(BootStage::VgaInit));
    assert_eq!(BootStage::KernelTransfer.next(), Some(BootStage::Complete));
    assert_eq!(BootStage::Complete.next(), None);
}

#[test]
fn test_boot_stage_prev() {
    assert_eq!(BootStage::Entry.prev(), None);
    assert_eq!(BootStage::SerialInit.prev(), Some(BootStage::Entry));
    assert_eq!(BootStage::Complete.prev(), Some(BootStage::KernelTransfer));
}

#[test]
fn test_boot_stage_is_complete() {
    assert!(!BootStage::Entry.is_complete());
    assert!(!BootStage::KernelTransfer.is_complete());
    assert!(BootStage::Complete.is_complete());
}

#[test]
fn test_boot_stage_is_early() {
    assert!(BootStage::Entry.is_early());
    assert!(BootStage::SerialInit.is_early());
    assert!(BootStage::VgaInit.is_early());
    assert!(BootStage::CpuDetect.is_early());
    assert!(!BootStage::GdtSetup.is_early());
    assert!(!BootStage::Complete.is_early());
}

#[test]
fn test_boot_stage_has_interrupts() {
    assert!(!BootStage::Entry.has_interrupts());
    assert!(!BootStage::GdtSetup.has_interrupts());
    assert!(BootStage::IdtSetup.has_interrupts());
    assert!(BootStage::MemoryValidation.has_interrupts());
    assert!(BootStage::KernelTransfer.has_interrupts());
    assert!(BootStage::Complete.has_interrupts());
}

#[test]
fn test_boot_stage_all() {
    let stages: Vec<BootStage> = BootStage::all().collect();
    assert_eq!(stages.len(), BootStage::COUNT);
    assert_eq!(stages[0], BootStage::Entry);
    assert_eq!(stages[10], BootStage::Complete);
}

#[test]
fn test_boot_stage_ordering() {
    assert!(BootStage::Entry < BootStage::SerialInit);
    assert!(BootStage::SerialInit < BootStage::Complete);
}

#[test]
fn test_boot_stage_default() {
    assert_eq!(BootStage::default(), BootStage::Entry);
}

#[test]
fn test_exception_context_default() {
    let ctx = ExceptionContext::default();
    assert_eq!(ctx.rip, 0);
    assert_eq!(ctx.rsp, 0);
    assert_eq!(ctx.rax, 0);
    assert_eq!(ctx.vector, 0);
    assert_eq!(ctx.error_code, 0);
}

#[test]
fn test_exception_context_instruction_pointer() {
    let mut ctx = ExceptionContext::default();
    ctx.rip = 0x1234;
    assert_eq!(ctx.instruction_pointer(), 0x1234);
}

#[test]
fn test_exception_context_stack_pointer() {
    let mut ctx = ExceptionContext::default();
    ctx.rsp = 0x5678;
    assert_eq!(ctx.stack_pointer(), 0x5678);
}

#[test]
fn test_exception_context_code_segment() {
    let mut ctx = ExceptionContext::default();
    ctx.cs = 0x08;
    assert_eq!(ctx.code_segment(), 0x08);
}

#[test]
fn test_exception_context_is_user_mode() {
    let mut ctx = ExceptionContext::default();
    ctx.cs = 0x08;
    assert!(!ctx.is_user_mode());
    ctx.cs = 0x1B;
    assert!(ctx.is_user_mode());
}

#[test]
fn test_exception_context_is_kernel_mode() {
    let mut ctx = ExceptionContext::default();
    ctx.cs = 0x08;
    assert!(ctx.is_kernel_mode());
    ctx.cs = 0x1B;
    assert!(!ctx.is_kernel_mode());
}

#[test]
fn test_exception_context_has_error_code() {
    let mut ctx = ExceptionContext::default();
    ctx.vector = 8;
    assert!(ctx.has_error_code());
    ctx.vector = 14;
    assert!(ctx.has_error_code());
    ctx.vector = 13;
    assert!(ctx.has_error_code());
    ctx.vector = 0;
    assert!(!ctx.has_error_code());
    ctx.vector = 6;
    assert!(!ctx.has_error_code());
}

#[test]
fn test_boot_stats_default() {
    let stats = BootStats::default();
    assert_eq!(stats.stage, 0);
    assert_eq!(stats.error, 0);
    assert!(!stats.complete);
    assert_eq!(stats.boot_tsc, 0);
    assert_eq!(stats.complete_tsc, 0);
    assert_eq!(stats.exceptions, 0);
}

#[test]
fn test_boot_stats_duration_tsc() {
    let stats = BootStats {
        boot_tsc: 1000,
        complete_tsc: 5000,
        ..Default::default()
    };
    assert_eq!(stats.duration_tsc(), 4000);
}

#[test]
fn test_boot_stats_duration_tsc_zero() {
    let stats = BootStats::default();
    assert_eq!(stats.duration_tsc(), 0);
}

#[test]
fn test_boot_stats_current_stage() {
    let mut stats = BootStats::default();
    stats.stage = 5;
    assert_eq!(stats.current_stage(), BootStage::SegmentReload);
}

#[test]
fn test_boot_stats_is_complete() {
    let mut stats = BootStats::default();
    assert!(!stats.is_complete());
    stats.complete = true;
    assert!(stats.is_complete());
}

#[test]
fn test_boot_stats_has_error() {
    let mut stats = BootStats::default();
    assert!(!stats.has_error());
    stats.error = 1;
    assert!(stats.has_error());
}

#[test]
fn test_exception_context_copy() {
    let ctx = ExceptionContext::default();
    let copy = ctx;
    assert_eq!(copy.rip, ctx.rip);
}

#[test]
fn test_exception_context_clone() {
    let mut ctx = ExceptionContext::default();
    ctx.rax = 42;
    let cloned = ctx.clone();
    assert_eq!(cloned.rax, 42);
}

#[test]
fn test_boot_stats_copy() {
    let stats = BootStats::default();
    let copy = stats;
    assert_eq!(copy.stage, stats.stage);
}
