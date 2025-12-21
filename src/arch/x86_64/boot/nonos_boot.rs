// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//
// NØNOS x86_64 Boot Sequence
//
// This module orchestrates the complete boot process for x86_64, coordinating
// initialization of all architecture-specific subsystems in the correct order.
//
// Boot Stages:
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  Stage │ Description                    │ Subsystem                     │
// │────────┼────────────────────────────────┼───────────────────────────────│
// │   0    │ Entry point reached            │ Boot                          │
// │   1    │ Serial port initialized        │ serial::init()                │
// │   2    │ VGA display initialized        │ vga::init()                   │
// │   3    │ CPU features detected          │ cpu::init()                   │
// │   4    │ GDT and TSS loaded             │ gdt::init()                   │
// │   5    │ Segment registers reloaded     │ gdt::reload_segments()        │
// │   6    │ SSE/AVX enabled                │ cpu control registers         │
// │   7    │ IDT loaded                     │ idt::init()                   │
// │   8    │ Memory validated               │ Page table checks             │
// │   9    │ Kernel transfer                │ kernel_main()                 │
// │  10    │ Boot complete                  │ All subsystems ready          │
// └─────────────────────────────────────────────────────────────────────────┘

use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU64, AtomicBool, Ordering};

use crate::arch::x86_64::serial;
use crate::arch::x86_64::vga;
use crate::arch::x86_64::cpu;
use crate::arch::x86_64::gdt;
use crate::arch::x86_64::idt;

// ============================================================================
// Error Types
// ============================================================================

/// Boot error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootError {
    /// No error
    None = 0,
    /// Serial initialization failed
    SerialInitFailed = 1,
    /// VGA initialization failed
    VgaInitFailed = 2,
    /// CPU initialization failed
    CpuInitFailed = 3,
    /// CPUID instruction not available
    NoCpuid = 4,
    /// Long mode not supported
    NoLongMode = 5,
    /// SSE not supported (required for x86_64)
    NoSse = 6,
    /// SSE2 not supported (required for x86_64)
    NoSse2 = 7,
    /// FXSAVE/FXRSTOR not supported
    NoFxsr = 8,
    /// APIC not available
    NoApic = 9,
    /// MSR instructions not supported
    NoMsr = 10,
    /// PAE not supported
    NoPae = 11,
    /// GDT initialization failed
    GdtInitFailed = 12,
    /// GDT load failed
    GdtLoadFailed = 13,
    /// TSS load failed
    TssLoadFailed = 14,
    /// IDT initialization failed
    IdtInitFailed = 15,
    /// IDT load failed
    IdtLoadFailed = 16,
    /// SSE/AVX enable failed
    SseEnableFailed = 17,
    /// Page table invalid (CR3 = 0)
    InvalidPageTable = 18,
    /// Paging not enabled
    PagingNotEnabled = 19,
    /// PAE not enabled in CR4
    PaeNotEnabled = 20,
    /// Long mode not active
    LongModeNotActive = 21,
    /// Higher-half not mapped
    NoHigherHalf = 22,
    /// Memory validation failed
    MemoryValidationFailed = 23,
    /// Stack setup failed
    StackSetupFailed = 24,
    /// Boot timeout
    Timeout = 25,
    /// Unknown error
    Unknown = 255,
}

impl BootError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::SerialInitFailed => "serial port initialization failed",
            Self::VgaInitFailed => "VGA display initialization failed",
            Self::CpuInitFailed => "CPU detection/initialization failed",
            Self::NoCpuid => "CPUID instruction not available",
            Self::NoLongMode => "long mode (x86_64) not supported",
            Self::NoSse => "SSE not supported (required for x86_64)",
            Self::NoSse2 => "SSE2 not supported (required for x86_64)",
            Self::NoFxsr => "FXSAVE/FXRSTOR not supported",
            Self::NoApic => "APIC not available",
            Self::NoMsr => "MSR instructions not supported",
            Self::NoPae => "PAE not supported",
            Self::GdtInitFailed => "GDT initialization failed",
            Self::GdtLoadFailed => "failed to load GDT",
            Self::TssLoadFailed => "failed to load TSS",
            Self::IdtInitFailed => "IDT initialization failed",
            Self::IdtLoadFailed => "failed to load IDT",
            Self::SseEnableFailed => "SSE/AVX enablement failed",
            Self::InvalidPageTable => "invalid page table (CR3 = 0)",
            Self::PagingNotEnabled => "paging not enabled in CR0",
            Self::PaeNotEnabled => "PAE not enabled in CR4",
            Self::LongModeNotActive => "long mode not active in EFER",
            Self::NoHigherHalf => "higher-half kernel mapping not present",
            Self::MemoryValidationFailed => "memory validation failed",
            Self::StackSetupFailed => "interrupt stack setup failed",
            Self::Timeout => "boot sequence timeout",
            Self::Unknown => "unknown boot error",
        }
    }

    /// Convert from u8
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::SerialInitFailed,
            2 => Self::VgaInitFailed,
            3 => Self::CpuInitFailed,
            4 => Self::NoCpuid,
            5 => Self::NoLongMode,
            6 => Self::NoSse,
            7 => Self::NoSse2,
            8 => Self::NoFxsr,
            9 => Self::NoApic,
            10 => Self::NoMsr,
            11 => Self::NoPae,
            12 => Self::GdtInitFailed,
            13 => Self::GdtLoadFailed,
            14 => Self::TssLoadFailed,
            15 => Self::IdtInitFailed,
            16 => Self::IdtLoadFailed,
            17 => Self::SseEnableFailed,
            18 => Self::InvalidPageTable,
            19 => Self::PagingNotEnabled,
            20 => Self::PaeNotEnabled,
            21 => Self::LongModeNotActive,
            22 => Self::NoHigherHalf,
            23 => Self::MemoryValidationFailed,
            24 => Self::StackSetupFailed,
            25 => Self::Timeout,
            _ => Self::Unknown,
        }
    }
}

// ============================================================================
// Boot Stage
// ============================================================================

/// Boot stage identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum BootStage {
    /// Initial entry from bootloader
    Entry = 0,
    /// Serial port initialized
    SerialInit = 1,
    /// VGA display initialized
    VgaInit = 2,
    /// CPU features detected
    CpuDetect = 3,
    /// GDT and TSS setup
    GdtSetup = 4,
    /// Segment registers reloaded
    SegmentReload = 5,
    /// SSE/AVX enabled
    SseEnable = 6,
    /// IDT setup
    IdtSetup = 7,
    /// Memory validation
    MemoryValidation = 8,
    /// Transfer to kernel main
    KernelTransfer = 9,
    /// Boot complete
    Complete = 10,
}

impl BootStage {
    /// Returns stage name
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "Entry",
            Self::SerialInit => "Serial Init",
            Self::VgaInit => "VGA Init",
            Self::CpuDetect => "CPU Detection",
            Self::GdtSetup => "GDT/TSS Setup",
            Self::SegmentReload => "Segment Reload",
            Self::SseEnable => "SSE/AVX Enable",
            Self::IdtSetup => "IDT Setup",
            Self::MemoryValidation => "Memory Validation",
            Self::KernelTransfer => "Kernel Transfer",
            Self::Complete => "Complete",
        }
    }

    /// Convert from u8
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Entry,
            1 => Self::SerialInit,
            2 => Self::VgaInit,
            3 => Self::CpuDetect,
            4 => Self::GdtSetup,
            5 => Self::SegmentReload,
            6 => Self::SseEnable,
            7 => Self::IdtSetup,
            8 => Self::MemoryValidation,
            9 => Self::KernelTransfer,
            _ => Self::Complete,
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Boot stack address (1 MB mark, below kernel)
const BOOT_STACK_BASE: u64 = 0x100000;
/// Boot stack size (64 KB)
const BOOT_STACK_SIZE: u64 = 0x10000;
/// Boot stack top (16-byte aligned)
const BOOT_STACK_TOP: u64 = BOOT_STACK_BASE + BOOT_STACK_SIZE - 16;

/// Higher-half base address
const HIGHER_HALF_BASE: u64 = 0xFFFF_8000_0000_0000;
/// Kernel base address
const KERNEL_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// MSR: Extended Feature Enable Register
const MSR_EFER: u32 = 0xC000_0080;

// Re-export segment selectors from GDT module
pub use crate::arch::x86_64::gdt::{KERNEL_CS, KERNEL_DS, USER_CS, USER_DS, TSS_SEL};

// ============================================================================
// Global Boot State
// ============================================================================

/// Current boot stage
static BOOT_STAGE: AtomicU8 = AtomicU8::new(0);
/// Boot error code
static BOOT_ERROR: AtomicU8 = AtomicU8::new(0);
/// Boot complete flag
static BOOT_COMPLETE: AtomicBool = AtomicBool::new(false);
/// TSC value at boot start
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);
/// Exception count during boot
static EXCEPTION_COUNT: AtomicU64 = AtomicU64::new(0);
/// Boot stage timestamps (TSC values for each stage)
static STAGE_TSC: [AtomicU64; 11] = [
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
    AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
];

// ============================================================================
// Structures (Re-exports from subsystems)
// ============================================================================

/// Re-export CPU features from cpu module
pub use crate::arch::x86_64::cpu::CpuFeatures;

/// Re-export TSS from gdt module
pub use crate::arch::x86_64::gdt::Tss;

/// Re-export interrupt frame from idt module
pub use crate::arch::x86_64::idt::InterruptFrame;

/// Exception context with saved registers
#[repr(C)]
pub struct ExceptionContext {
    /// General purpose registers (pushed by handler)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    /// Exception vector number
    pub vector: u64,
    /// Error code (0 if not applicable)
    pub error_code: u64,
    /// CPU-pushed interrupt frame
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// ============================================================================
// Boot Statistics
// ============================================================================

/// Boot statistics snapshot
#[derive(Clone, Copy, Default)]
pub struct BootStats {
    /// Current boot stage
    pub stage: u8,
    /// Error code (0 = none)
    pub error: u8,
    /// Boot complete flag
    pub complete: bool,
    /// TSC at boot start
    pub boot_tsc: u64,
    /// TSC at boot complete (or current if not complete)
    pub complete_tsc: u64,
    /// Exception count during boot
    pub exceptions: u64,
    /// Per-stage TSC timestamps
    pub stage_tsc: [u64; 11],
}

impl BootStats {
    /// Calculate boot duration in TSC ticks
    pub fn duration_tsc(&self) -> u64 {
        if self.complete_tsc > self.boot_tsc {
            self.complete_tsc - self.boot_tsc
        } else {
            0
        }
    }
}

// ============================================================================
// Low-level Helpers
// ============================================================================

/// Read Time Stamp Counter
#[inline]
unsafe fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
    ((hi as u64) << 32) | (lo as u64)
}

/// Read MSR
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Read CR0
#[inline]
unsafe fn read_cr0() -> u64 {
    let value: u64;
    asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

/// Write CR0
#[inline]
unsafe fn write_cr0(value: u64) {
    asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags));
}

/// Read CR3
#[inline]
unsafe fn read_cr3() -> u64 {
    let value: u64;
    asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

/// Read CR4
#[inline]
unsafe fn read_cr4() -> u64 {
    let value: u64;
    asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    value
}

/// Write CR4
#[inline]
unsafe fn write_cr4(value: u64) {
    asm!("mov cr4, {}", in(reg) value, options(nomem, nostack, preserves_flags));
}

/// Write XCR0 (extended control register)
#[inline]
unsafe fn write_xcr0(value: u64) {
    asm!(
        "xor ecx, ecx",
        "xsetbv",
        in("eax") value as u32,
        in("edx") (value >> 32) as u32,
        out("ecx") _,
        options(nomem, nostack)
    );
}

// ============================================================================
// Stage Management
// ============================================================================

/// Set current boot stage and record timestamp
fn set_stage(stage: BootStage) {
    let tsc = unsafe { rdtsc() };
    BOOT_STAGE.store(stage as u8, Ordering::SeqCst);
    if (stage as usize) < STAGE_TSC.len() {
        STAGE_TSC[stage as usize].store(tsc, Ordering::Relaxed);
    }
}

/// Log message to serial (if available)
fn log(msg: &str) {
    if serial::is_initialized() {
        serial::write_str(msg);
    }
}

/// Log stage completion
fn log_stage_complete(stage: BootStage, success: bool) {
    if serial::is_initialized() {
        if success {
            serial::write_str("[OK] ");
        } else {
            serial::write_str("[FAIL] ");
        }
        serial::write_str(stage.as_str());
        serial::write_str("\n");
    }

    if vga::is_initialized() {
        let row = 2 + stage as usize;
        let status = if success { "[*]" } else { "[!]" };
        let color = if success {
            vga::ColorCode::new(vga::Color::LightGreen, vga::Color::Black)
        } else {
            vga::ColorCode::new(vga::Color::LightRed, vga::Color::Black)
        };

        // Write status indicator
        vga::set_color(vga::Color::White, vga::Color::Black);
        // We'd need position control here - simplified for now
    }
}

// ============================================================================
// SSE/AVX Enablement
// ============================================================================

/// Enable SSE and optionally AVX
unsafe fn enable_sse_avx() -> Result<(), BootError> {
    // Get CPU features
    let features = cpu::features();

    // Verify SSE is available (required for x86_64)
    if !features.sse {
        return Err(BootError::NoSse);
    }
    if !features.sse2 {
        return Err(BootError::NoSse2);
    }
    if !features.fxsr {
        return Err(BootError::NoFxsr);
    }

    // Enable SSE in CR0
    let mut cr0 = read_cr0();
    cr0 &= !(1 << 2); // Clear EM (no x87 emulation)
    cr0 |= 1 << 1;    // Set MP (monitor coprocessor)
    write_cr0(cr0);

    // Enable SSE in CR4
    let mut cr4 = read_cr4();
    cr4 |= 1 << 9;    // OSFXSR - enable FXSAVE/FXRSTOR
    cr4 |= 1 << 10;   // OSXMMEXCPT - enable SSE exceptions

    // Enable XSAVE if available (needed for AVX)
    if features.xsave {
        cr4 |= 1 << 18; // OSXSAVE
    }

    write_cr4(cr4);

    log("  SSE enabled\n");

    // Enable AVX if available and XSAVE is enabled
    if features.avx && features.xsave {
        // Set XCR0 to enable x87 + SSE + AVX state
        // Bit 0: x87 FPU state
        // Bit 1: SSE state (XMM registers)
        // Bit 2: AVX state (YMM upper halves)
        let xcr0: u64 = 0x07;
        write_xcr0(xcr0);
        log("  AVX enabled\n");
    }

    // Enable AVX-512 if available
    if features.avx512f && features.xsave {
        // Additional bits for AVX-512:
        // Bit 5: opmask (k0-k7)
        // Bit 6: ZMM upper 256 bits (ZMM0-15)
        // Bit 7: ZMM16-31
        let xcr0: u64 = 0x07 | (1 << 5) | (1 << 6) | (1 << 7);
        write_xcr0(xcr0);
        log("  AVX-512 enabled\n");
    }

    Ok(())
}

// ============================================================================
// Memory Validation
// ============================================================================

/// Validate paging and memory configuration
unsafe fn validate_memory() -> Result<(), BootError> {
    // Check CR3 (page table base)
    let cr3 = read_cr3();
    if cr3 == 0 {
        return Err(BootError::InvalidPageTable);
    }

    log("  CR3: 0x");
    log_hex(cr3);
    log("\n");

    // Check CR0 for paging enabled
    let cr0 = read_cr0();
    if cr0 & (1 << 31) == 0 {
        return Err(BootError::PagingNotEnabled);
    }

    // Check CR4 for PAE
    let cr4 = read_cr4();
    if cr4 & (1 << 5) == 0 {
        return Err(BootError::PaeNotEnabled);
    }

    // Check EFER for long mode active
    let efer = rdmsr(MSR_EFER);
    if efer & (1 << 10) == 0 {
        return Err(BootError::LongModeNotActive);
    }

    log("  Paging: enabled\n");
    log("  PAE: enabled\n");
    log("  Long mode: active\n");

    Ok(())
}

/// Log a hex value to serial
fn log_hex(value: u64) {
    if !serial::is_initialized() {
        return;
    }

    let hex = b"0123456789ABCDEF";
    let mut buf = [0u8; 16];

    for i in 0..16 {
        let nibble = ((value >> ((15 - i) * 4)) & 0xF) as usize;
        buf[i] = hex[nibble];
    }

    // Find first non-zero digit (or keep at least one)
    let start = buf.iter().position(|&b| b != b'0').unwrap_or(15);

    for &b in &buf[start..] {
        let _ = serial::write_byte(b);
    }
}

// ============================================================================
// Boot Panic
// ============================================================================

/// Handle fatal boot error
unsafe fn boot_panic(error: BootError) -> ! {
    BOOT_ERROR.store(error as u8, Ordering::SeqCst);

    // Try to output to serial
    if serial::is_initialized() {
        serial::write_str("\n!!! BOOT PANIC: ");
        serial::write_str(error.as_str());
        serial::write_str("\n");
    }

    // Try to output to VGA
    if vga::is_initialized() {
        vga::enter_panic_mode();
        vga::set_color(vga::Color::LightRed, vga::Color::Black);
        vga::write_str("\n\nBOOT PANIC: ");
        vga::write_str(error.as_str());
        vga::write_str("\n");
    }

    // Halt forever
    loop {
        asm!("cli; hlt", options(nomem, nostack, preserves_flags));
    }
}

// ============================================================================
// Entry Point
// ============================================================================

/// Architecture entry point from bootloader
///
/// This is the first Rust code executed after the bootloader transfers control.
/// It sets up a known-good stack and calls the main boot sequence.
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _arch_start() -> ! {
    // Setup boot stack (16-byte aligned for SSE)
    asm!(
        "mov rsp, {}",
        "mov rbp, rsp",
        "xor rbp, rbp",  // Clear frame pointer for stack traces
        "call {}",
        in(reg) BOOT_STACK_TOP,
        sym boot_main,
        options(noreturn)
    );
}

/// Main boot sequence
///
/// Initializes all architecture subsystems in the correct order:
/// 1. Serial (for debug output)
/// 2. VGA (for visual feedback)
/// 3. CPU (feature detection)
/// 4. GDT/TSS (segmentation)
/// 5. SSE/AVX (SIMD)
/// 6. IDT (exception handling)
/// 7. Memory validation
/// 8. Transfer to kernel
#[no_mangle]
unsafe extern "C" fn boot_main() -> ! {
    // Record boot start timestamp
    BOOT_TSC.store(rdtsc(), Ordering::SeqCst);

    // ========== Stage 0: Entry ==========
    set_stage(BootStage::Entry);

    // ========== Stage 1: Serial Init ==========
    set_stage(BootStage::SerialInit);
    match serial::init() {
        Ok(()) => {
            log("\n");
            log("================================================================================\n");
            log("                           NONOS x86_64 Boot                                   \n");
            log("================================================================================\n");
            log("\n");
            log_stage_complete(BootStage::SerialInit, true);
        }
        Err(_) => {
            // Continue without serial - VGA will show status
        }
    }

    // ========== Stage 2: VGA Init ==========
    set_stage(BootStage::VgaInit);
    match vga::init() {
        Ok(()) => {
            vga::clear();
            vga::set_color(vga::Color::White, vga::Color::Blue);
            vga::write_str(" NONOS x86_64 Boot ");
            vga::set_color(vga::Color::LightGray, vga::Color::Black);
            vga::write_str("\n\n");
            log_stage_complete(BootStage::VgaInit, true);
        }
        Err(_) => {
            log_stage_complete(BootStage::VgaInit, false);
            // Continue - serial is enough for diagnostics
        }
    }

    // ========== Stage 3: CPU Detection ==========
    set_stage(BootStage::CpuDetect);
    match cpu::init() {
        Ok(()) => {
            log_stage_complete(BootStage::CpuDetect, true);

            // Print CPU info
            let features = cpu::features();
            let vendor = cpu::vendor();

            log("  Vendor: ");
            match vendor {
                cpu::CpuVendor::Intel => log("Intel"),
                cpu::CpuVendor::Amd => log("AMD"),
                cpu::CpuVendor::Unknown => log("Unknown"),
            }
            log("\n");

            log("  Features:");
            if features.sse { log(" SSE"); }
            if features.sse2 { log(" SSE2"); }
            if features.sse3 { log(" SSE3"); }
            if features.ssse3 { log(" SSSE3"); }
            if features.sse4_1 { log(" SSE4.1"); }
            if features.sse4_2 { log(" SSE4.2"); }
            if features.avx { log(" AVX"); }
            if features.avx2 { log(" AVX2"); }
            if features.avx512f { log(" AVX512F"); }
            if features.aes_ni { log(" AES"); }
            log("\n");

            // Display on VGA
            if vga::is_initialized() {
                vga::write_str("CPU: ");
                match vendor {
                    cpu::CpuVendor::Intel => vga::write_str("Intel"),
                    cpu::CpuVendor::Amd => vga::write_str("AMD"),
                    cpu::CpuVendor::Unknown => vga::write_str("Unknown"),
                }
                vga::write_str("\n");
            }
        }
        Err(e) => {
            log_stage_complete(BootStage::CpuDetect, false);
            // Map CPU error to boot error
            match e {
                cpu::CpuError::NoCpuid => boot_panic(BootError::NoCpuid),
                cpu::CpuError::NoLongMode => boot_panic(BootError::NoLongMode),
                _ => boot_panic(BootError::CpuInitFailed),
            }
        }
    }

    // Validate required CPU features
    let features = cpu::features();
    if !features.sse {
        boot_panic(BootError::NoSse);
    }
    if !features.sse2 {
        boot_panic(BootError::NoSse2);
    }
    if !features.apic {
        boot_panic(BootError::NoApic);
    }
    if !features.msr {
        boot_panic(BootError::NoMsr);
    }

    // ========== Stage 4: GDT/TSS Setup ==========
    set_stage(BootStage::GdtSetup);
    match gdt::init() {
        Ok(()) => {
            log_stage_complete(BootStage::GdtSetup, true);
        }
        Err(e) => {
            log_stage_complete(BootStage::GdtSetup, false);
            match e {
                gdt::GdtError::AlreadyInitialized => {
                    log("  GDT already initialized\n");
                }
                _ => boot_panic(BootError::GdtInitFailed),
            }
        }
    }

    // ========== Stage 5: Segment Reload ==========
    set_stage(BootStage::SegmentReload);
    gdt::reload_segments();
    log_stage_complete(BootStage::SegmentReload, true);

    // ========== Stage 6: SSE/AVX Enable ==========
    set_stage(BootStage::SseEnable);
    match enable_sse_avx() {
        Ok(()) => {
            log_stage_complete(BootStage::SseEnable, true);
        }
        Err(e) => {
            log_stage_complete(BootStage::SseEnable, false);
            boot_panic(e);
        }
    }

    // ========== Stage 7: IDT Setup ==========
    set_stage(BootStage::IdtSetup);
    match idt::init() {
        Ok(()) => {
            log_stage_complete(BootStage::IdtSetup, true);
        }
        Err(e) => {
            log_stage_complete(BootStage::IdtSetup, false);
            match e {
                idt::IdtError::AlreadyInitialized => {
                    log("  IDT already initialized\n");
                }
                _ => boot_panic(BootError::IdtInitFailed),
            }
        }
    }

    // ========== Stage 8: Memory Validation ==========
    set_stage(BootStage::MemoryValidation);
    match validate_memory() {
        Ok(()) => {
            log_stage_complete(BootStage::MemoryValidation, true);
        }
        Err(e) => {
            log_stage_complete(BootStage::MemoryValidation, false);
            boot_panic(e);
        }
    }

    // ========== Stage 9: Kernel Transfer ==========
    set_stage(BootStage::KernelTransfer);
    log_stage_complete(BootStage::KernelTransfer, true);
    log("\nBoot complete, transferring to kernel_main\n");
    log("================================================================================\n\n");

    // ========== Stage 10: Complete ==========
    set_stage(BootStage::Complete);
    BOOT_COMPLETE.store(true, Ordering::SeqCst);

    // Record completion time
    let complete_tsc = rdtsc();
    STAGE_TSC[BootStage::Complete as usize].store(complete_tsc, Ordering::Relaxed);

    // Calculate and log boot time
    let boot_tsc = BOOT_TSC.load(Ordering::Relaxed);
    let duration = complete_tsc - boot_tsc;
    log("Boot duration: ");
    log_hex(duration);
    log(" TSC ticks\n\n");

    // Display completion on VGA
    if vga::is_initialized() {
        vga::set_color(vga::Color::LightGreen, vga::Color::Black);
        vga::write_str("\nBoot complete!\n");
        vga::set_color(vga::Color::LightGray, vga::Color::Black);
    }

    // Transfer to kernel main
    crate::kernel_main();
}

// ============================================================================
// Public API
// ============================================================================

/// Get current boot stage
#[inline]
pub fn boot_stage() -> BootStage {
    BootStage::from_u8(BOOT_STAGE.load(Ordering::Acquire))
}

/// Get boot error (if any)
#[inline]
pub fn boot_error() -> BootError {
    BootError::from_u8(BOOT_ERROR.load(Ordering::Acquire))
}

/// Check if boot is complete
#[inline]
pub fn is_boot_complete() -> bool {
    BOOT_COMPLETE.load(Ordering::Acquire)
}

/// Get TSC value at boot start
#[inline]
pub fn boot_tsc() -> u64 {
    BOOT_TSC.load(Ordering::Acquire)
}

/// Get exception count during boot
#[inline]
pub fn exception_count() -> u64 {
    EXCEPTION_COUNT.load(Ordering::Acquire)
}

/// Increment exception count (called by exception handlers)
#[inline]
pub fn increment_exception_count() {
    EXCEPTION_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Get CPU features detected at boot
#[inline]
pub fn cpu_features() -> CpuFeatures {
    cpu::features()
}

/// Get CPU family
#[inline]
pub fn cpu_family() -> u8 {
    let id = cpu::cpu_id();
    id.family
}

/// Get CPU model
#[inline]
pub fn cpu_model() -> u8 {
    let id = cpu::cpu_id();
    id.model
}

/// Get CPU stepping
#[inline]
pub fn cpu_stepping() -> u8 {
    let id = cpu::cpu_id();
    id.stepping
}

/// Get current kernel stack pointer from TSS (BSP)
#[inline]
pub fn kernel_stack() -> u64 {
    gdt::get_kernel_stack(0).unwrap_or(0)
}

/// Get boot statistics
pub fn get_stats() -> BootStats {
    let mut stage_tsc = [0u64; 11];
    for i in 0..11 {
        stage_tsc[i] = STAGE_TSC[i].load(Ordering::Relaxed);
    }

    BootStats {
        stage: BOOT_STAGE.load(Ordering::Relaxed),
        error: BOOT_ERROR.load(Ordering::Relaxed),
        complete: BOOT_COMPLETE.load(Ordering::Relaxed),
        boot_tsc: BOOT_TSC.load(Ordering::Relaxed),
        complete_tsc: stage_tsc[BootStage::Complete as usize],
        exceptions: EXCEPTION_COUNT.load(Ordering::Relaxed),
        stage_tsc,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(BootError::None.as_str(), "no error");
        assert_eq!(BootError::NoSse.as_str(), "SSE not supported (required for x86_64)");
        assert_eq!(BootError::InvalidPageTable.as_str(), "invalid page table (CR3 = 0)");
    }

    #[test]
    fn test_error_from_u8() {
        assert_eq!(BootError::from_u8(0), BootError::None);
        assert_eq!(BootError::from_u8(6), BootError::NoSse);
        assert_eq!(BootError::from_u8(255), BootError::Unknown);
    }

    #[test]
    fn test_stage_names() {
        assert_eq!(BootStage::Entry.as_str(), "Entry");
        assert_eq!(BootStage::Complete.as_str(), "Complete");
    }

    #[test]
    fn test_stage_from_u8() {
        assert_eq!(BootStage::from_u8(0), BootStage::Entry);
        assert_eq!(BootStage::from_u8(10), BootStage::Complete);
        assert_eq!(BootStage::from_u8(100), BootStage::Complete);
    }

    #[test]
    fn test_stage_ordering() {
        assert!(BootStage::Entry < BootStage::SerialInit);
        assert!(BootStage::SerialInit < BootStage::Complete);
    }

    #[test]
    fn test_boot_stats_duration() {
        let stats = BootStats {
            boot_tsc: 1000,
            complete_tsc: 5000,
            ..Default::default()
        };
        assert_eq!(stats.duration_tsc(), 4000);
    }

    #[test]
    fn test_boot_stats_duration_zero() {
        let stats = BootStats::default();
        assert_eq!(stats.duration_tsc(), 0);
    }
}
