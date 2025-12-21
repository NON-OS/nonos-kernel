// NØNOS Operating System
// Copyright (C) 2024 NØNOS Contributors
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
// NØNOS x86_64 Global Descriptor Table
// x86_64 long mode:
// Flat memory model with kernel/user segments
// Task State Segment with Interrupt Stack Tables
// Per-CPU GDT support for SMP
// SYSCALL/SYSRET MSR configuration
// FS/GS base register management
// I/O permission bitmap support
//
// Architecture:
//
// ┌────────────────────────────────────────────────────────────────────┐
// │                          GDT Layout                                │
// ├────────────────────────────────────────────────────────────────────┤
// │  Index │ Selector │ Description              │ Access  │ Flags     │
// │────────┼──────────┼──────────────────────────┼─────────┼───────────│
// │    0   │  0x00    │ Null descriptor          │  0x00   │ 0x0       │
// │    1   │  0x08    │ Kernel Code 64-bit       │  0x9A   │ 0xA (L=1) │
// │    2   │  0x10    │ Kernel Data              │  0x92   │ 0xC       │
// │    3   │  0x18    │ User Data (for SYSCALL)  │  0xF2   │ 0xC       │
// │    4   │  0x20    │ User Code 64-bit         │  0xFA   │ 0xA (L=1) │
// │   5-6  │  0x28    │ TSS (16 bytes)           │  0x89   │ 0x0       │
// └────────────────────────────────────────────────────────────────────┘
//
// Segment Selector Format:
// ┌──────────────────────────────────────────────┐
// │  15                              3   2   1 0 │
// │ ┌────────────────────────────────┬───┬─────┐ │
// │ │           Index                │ TI│ RPL │ │
// │ └────────────────────────────────┴───┴─────┘ │
// │ TI = 0 (GDT), RPL = Ring (0-3)               │
// └──────────────────────────────────────────────┘
//
// TSS Layout (104 bytes):
// ┌────────────────────────────────────────────────────────┐
// │  Offset │ Size │ Description                           │
// │─────────┼──────┼───────────────────────────────────────│
// │  0x00   │  4   │ Reserved                              │
// │  0x04   │  8   │ RSP0 - Ring 0 stack                   │
// │  0x0C   │  8   │ RSP1 - Ring 1 stack (unused in x86_64)│
// │  0x14   │  8   │ RSP2 - Ring 2 stack (unused in x86_64)│
// │  0x1C   │  8   │ Reserved                              │
// │  0x24   │  8   │ IST1 - Interrupt Stack Table 1        │
// │  0x2C   │  8   │ IST2 - Interrupt Stack Table 2        │
// │  0x34   │  8   │ IST3 - Interrupt Stack Table 3        │
// │  0x3C   │  8   │ IST4 - Interrupt Stack Table 4        │
// │  0x44   │  8   │ IST5 - Interrupt Stack Table 5        │
// │  0x4C   │  8   │ IST6 - Interrupt Stack Table 6        │
// │  0x54   │  8   │ IST7 - Interrupt Stack Table 7        │
// │  0x5C   │  8   │ Reserved                              │
// │  0x64   │  2   │ Reserved                              │
// │  0x66   │  2   │ I/O Map Base Address                  │
// └────────────────────────────────────────────────────────┘

use core::arch::asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ============================================================================
// Error Types
// ============================================================================

/// GDT operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GdtError {
    /// No error
    None = 0,
    /// GDT not initialized
    NotInitialized = 1,
    /// Already initialized
    AlreadyInitialized = 2,
    /// Invalid segment selector
    InvalidSelector = 3,
    /// Invalid CPU ID
    InvalidCpuId = 4,
    /// IST index out of range (must be 1-7)
    InvalidIstIndex = 5,
    /// RSP index out of range (must be 0-2)
    InvalidRspIndex = 6,
    /// TSS not configured
    TssNotConfigured = 7,
    /// Stack allocation failed
    StackAllocationFailed = 8,
    /// GDT load failed
    LoadFailed = 9,
    /// TSS load failed
    TssLoadFailed = 10,
    /// Segment reload failed
    SegmentReloadFailed = 11,
    /// MSR write failed
    MsrWriteFailed = 12,
}

impl GdtError {
    /// Returns human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "no error",
            Self::NotInitialized => "GDT not initialized",
            Self::AlreadyInitialized => "GDT already initialized",
            Self::InvalidSelector => "invalid segment selector",
            Self::InvalidCpuId => "invalid CPU ID",
            Self::InvalidIstIndex => "IST index must be 1-7",
            Self::InvalidRspIndex => "RSP index must be 0-2",
            Self::TssNotConfigured => "TSS not configured",
            Self::StackAllocationFailed => "interrupt stack allocation failed",
            Self::LoadFailed => "GDT load failed",
            Self::TssLoadFailed => "TSS load failed",
            Self::SegmentReloadFailed => "segment register reload failed",
            Self::MsrWriteFailed => "MSR write failed",
        }
    }
}

// ============================================================================
// Constants
// ============================================================================

/// Maximum supported CPUs
pub const MAX_CPUS: usize = 256;

/// TSS size in bytes
pub const TSS_SIZE: usize = 104;

/// Number of IST entries (1-7, index 0 unused by convention)
pub const IST_COUNT: usize = 7;

/// Default interrupt stack size (16 KB)
pub const DEFAULT_STACK_SIZE: usize = 16384;

/// I/O permission bitmap size (8 KB for full 65536 ports)
pub const IOPB_SIZE: usize = 8192;

// ============================================================================
// Segment Selectors
// ============================================================================

/// Null segment selector
pub const SEL_NULL: u16 = 0x00;

/// Kernel code segment selector (Ring 0)
pub const SEL_KERNEL_CODE: u16 = 0x08;

/// Kernel data segment selector (Ring 0)
pub const SEL_KERNEL_DATA: u16 = 0x10;

/// User data segment selector (Ring 3)
/// Note: Placed before user code for SYSCALL compatibility
pub const SEL_USER_DATA: u16 = 0x18 | 3;

/// User code segment selector (Ring 3)
pub const SEL_USER_CODE: u16 = 0x20 | 3;

/// TSS segment selector
pub const SEL_TSS: u16 = 0x28;

/// Kernel code selector without RPL (raw index)
pub const SEL_KERNEL_CODE_RAW: u16 = 0x08;

/// Kernel data selector without RPL (raw index)
pub const SEL_KERNEL_DATA_RAW: u16 = 0x10;

/// User data selector without RPL (raw index)
pub const SEL_USER_DATA_RAW: u16 = 0x18;

/// User code selector without RPL (raw index)
pub const SEL_USER_CODE_RAW: u16 = 0x20;

// IST indices for exception handlers
/// IST index for double fault handler
pub const IST_DOUBLE_FAULT: usize = 1;
/// IST index for NMI handler
pub const IST_NMI: usize = 2;
/// IST index for machine check handler
pub const IST_MACHINE_CHECK: usize = 3;
/// IST index for debug exception handler
pub const IST_DEBUG: usize = 4;
/// IST index for page fault handler (optional)
pub const IST_PAGE_FAULT: usize = 5;
/// IST index for general protection handler (optional)
pub const IST_GP: usize = 6;

// GDT access byte flags
const ACCESS_PRESENT: u8 = 1 << 7;
const ACCESS_DPL_RING0: u8 = 0 << 5;
const ACCESS_DPL_RING3: u8 = 3 << 5;
const ACCESS_TYPE_SYSTEM: u8 = 0 << 4;
const ACCESS_TYPE_CODE_DATA: u8 = 1 << 4;
const ACCESS_EXECUTABLE: u8 = 1 << 3;
const ACCESS_DC: u8 = 1 << 2; // Direction/Conforming
const ACCESS_RW: u8 = 1 << 1; // Readable/Writable
const ACCESS_ACCESSED: u8 = 1 << 0;

// TSS type
const TSS_TYPE_AVAILABLE_64: u8 = 0x9;
const TSS_TYPE_BUSY_64: u8 = 0xB;

// GDT flags (granularity byte high nibble)
const FLAG_GRANULARITY: u8 = 1 << 7; // 4KB granularity
const FLAG_SIZE_32: u8 = 1 << 6;     // 32-bit segment
const FLAG_LONG_MODE: u8 = 1 << 5;   // 64-bit code segment

// ============================================================================
// GDT Entry Structures
// ============================================================================

/// Standard GDT entry (8 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GdtEntry {
    /// Segment limit bits 0-15
    pub limit_low: u16,
    /// Base address bits 0-15
    pub base_low: u16,
    /// Base address bits 16-23
    pub base_mid: u8,
    /// Access byte
    pub access: u8,
    /// Limit bits 16-19 (low nibble) and flags (high nibble)
    pub granularity: u8,
    /// Base address bits 24-31
    pub base_high: u8,
}

impl GdtEntry {
    /// Create a null descriptor
    pub const fn null() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            granularity: 0,
            base_high: 0,
        }
    }

    /// Create a 64-bit kernel code segment
    pub const fn kernel_code_64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_TYPE_CODE_DATA |
                    ACCESS_EXECUTABLE | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_LONG_MODE | 0x0F,
            base_high: 0,
        }
    }

    /// Create a kernel data segment
    pub const fn kernel_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING0 | ACCESS_TYPE_CODE_DATA | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_SIZE_32 | 0x0F,
            base_high: 0,
        }
    }

    /// Create a 64-bit user code segment
    pub const fn user_code_64() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_TYPE_CODE_DATA |
                    ACCESS_EXECUTABLE | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_LONG_MODE | 0x0F,
            base_high: 0,
        }
    }

    /// Create a user data segment
    pub const fn user_data() -> Self {
        Self {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access: ACCESS_PRESENT | ACCESS_DPL_RING3 | ACCESS_TYPE_CODE_DATA | ACCESS_RW,
            granularity: FLAG_GRANULARITY | FLAG_SIZE_32 | 0x0F,
            base_high: 0,
        }
    }

    /// Create from raw values
    pub const fn new(base: u32, limit: u32, access: u8, flags: u8) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access,
            granularity: ((limit >> 16) & 0x0F) as u8 | (flags & 0xF0),
            base_high: ((base >> 24) & 0xFF) as u8,
        }
    }

    /// Check if entry is present
    pub const fn is_present(&self) -> bool {
        self.access & ACCESS_PRESENT != 0
    }

    /// Get the DPL (privilege level)
    pub const fn dpl(&self) -> u8 {
        (self.access >> 5) & 0x3
    }

    /// Check if this is a code segment
    pub const fn is_code(&self) -> bool {
        self.access & ACCESS_TYPE_CODE_DATA != 0 && self.access & ACCESS_EXECUTABLE != 0
    }

    /// Check if this is a long mode (64-bit) segment
    pub const fn is_long_mode(&self) -> bool {
        self.granularity & FLAG_LONG_MODE != 0
    }
}

/// TSS entry in GDT (16 bytes in long mode)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct TssEntry {
    /// Segment limit bits 0-15
    pub limit_low: u16,
    /// Base address bits 0-15
    pub base_low: u16,
    /// Base address bits 16-23
    pub base_mid: u8,
    /// Access byte (type + DPL + present)
    pub access: u8,
    /// Limit bits 16-19 and flags
    pub limit_flags: u8,
    /// Base address bits 24-31
    pub base_high: u8,
    /// Base address bits 32-63
    pub base_upper: u32,
    /// Reserved (must be zero)
    pub reserved: u32,
}

impl TssEntry {
    /// Create an empty TSS entry
    pub const fn empty() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            limit_flags: 0,
            base_high: 0,
            base_upper: 0,
            reserved: 0,
        }
    }

    /// Create a TSS entry from address and limit
    pub fn new(base: u64, limit: u32) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access: ACCESS_PRESENT | ACCESS_TYPE_SYSTEM | TSS_TYPE_AVAILABLE_64,
            limit_flags: ((limit >> 16) & 0x0F) as u8,
            base_high: ((base >> 24) & 0xFF) as u8,
            base_upper: (base >> 32) as u32,
            reserved: 0,
        }
    }

    /// Update base address
    pub fn set_base(&mut self, base: u64) {
        self.base_low = (base & 0xFFFF) as u16;
        self.base_mid = ((base >> 16) & 0xFF) as u8;
        self.base_high = ((base >> 24) & 0xFF) as u8;
        self.base_upper = (base >> 32) as u32;
    }

    /// Get base address
    pub fn base(&self) -> u64 {
        (self.base_low as u64) |
        ((self.base_mid as u64) << 16) |
        ((self.base_high as u64) << 24) |
        ((self.base_upper as u64) << 32)
    }

    /// Check if TSS is busy
    pub fn is_busy(&self) -> bool {
        (self.access & 0x0F) == TSS_TYPE_BUSY_64
    }
}

// ============================================================================
// Task State Segment
// ============================================================================

/// Task State Segment for x86_64
#[repr(C, packed)]
pub struct Tss {
    /// Reserved
    reserved1: u32,
    /// Privilege stack pointers (RSP0, RSP1, RSP2)
    pub rsp: [u64; 3],
    /// Reserved
    reserved2: u64,
    /// Interrupt Stack Table (IST1-IST7)
    pub ist: [u64; 7],
    /// Reserved
    reserved3: u64,
    /// Reserved
    reserved4: u16,
    /// I/O Map Base Address offset
    pub iomap_base: u16,
}

impl Tss {
    /// Create a new empty TSS
    pub const fn new() -> Self {
        Self {
            reserved1: 0,
            rsp: [0; 3],
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: TSS_SIZE as u16, // No I/O map by default
        }
    }

    /// Set Ring 0 stack pointer (used on privilege level change)
    #[inline]
    pub fn set_rsp0(&mut self, rsp: u64) {
        self.rsp[0] = rsp;
    }

    /// Get Ring 0 stack pointer
    #[inline]
    pub fn rsp0(&self) -> u64 {
        self.rsp[0]
    }

    /// Set privilege level stack pointer (0-2)
    pub fn set_rsp(&mut self, ring: usize, rsp: u64) -> Result<(), GdtError> {
        if ring > 2 {
            return Err(GdtError::InvalidRspIndex);
        }
        self.rsp[ring] = rsp;
        Ok(())
    }

    /// Get privilege level stack pointer
    pub fn get_rsp(&self, ring: usize) -> Result<u64, GdtError> {
        if ring > 2 {
            return Err(GdtError::InvalidRspIndex);
        }
        Ok(self.rsp[ring])
    }

    /// Set Interrupt Stack Table entry (1-7)
    pub fn set_ist(&mut self, index: usize, stack_top: u64) -> Result<(), GdtError> {
        if index < 1 || index > 7 {
            return Err(GdtError::InvalidIstIndex);
        }
        self.ist[index - 1] = stack_top;
        Ok(())
    }

    /// Get Interrupt Stack Table entry (1-7)
    pub fn get_ist(&self, index: usize) -> Result<u64, GdtError> {
        if index < 1 || index > 7 {
            return Err(GdtError::InvalidIstIndex);
        }
        Ok(self.ist[index - 1])
    }

    /// Set I/O permission bitmap base offset
    pub fn set_iomap_base(&mut self, offset: u16) {
        self.iomap_base = offset;
    }

    /// Disable I/O permission bitmap (all ports denied)
    pub fn disable_iomap(&mut self) {
        self.iomap_base = TSS_SIZE as u16;
    }
}

// ============================================================================
// GDT Structure
// ============================================================================

/// Complete GDT structure (56 bytes)
#[repr(C, packed)]
pub struct Gdt {
    /// Null descriptor (required)
    pub null: GdtEntry,
    /// Kernel code segment (64-bit)
    pub kernel_code: GdtEntry,
    /// Kernel data segment
    pub kernel_data: GdtEntry,
    /// User data segment (before code for SYSCALL)
    pub user_data: GdtEntry,
    /// User code segment (64-bit)
    pub user_code: GdtEntry,
    /// TSS descriptor (16 bytes)
    pub tss: TssEntry,
}

impl Gdt {
    /// Create a new GDT with standard segments
    pub const fn new() -> Self {
        Self {
            null: GdtEntry::null(),
            kernel_code: GdtEntry::kernel_code_64(),
            kernel_data: GdtEntry::kernel_data(),
            user_data: GdtEntry::user_data(),
            user_code: GdtEntry::user_code_64(),
            tss: TssEntry::empty(),
        }
    }

    /// Set TSS entry
    pub fn set_tss(&mut self, tss_addr: u64) {
        self.tss = TssEntry::new(tss_addr, (TSS_SIZE - 1) as u32);
    }

    /// Get GDT size in bytes
    pub const fn size() -> usize {
        size_of::<Self>()
    }
}

/// GDT descriptor pointer (GDTR format)
#[repr(C, packed)]
pub struct GdtPtr {
    /// GDT size minus one
    pub limit: u16,
    /// GDT base address
    pub base: u64,
}

impl GdtPtr {
    /// Create from GDT reference
    pub fn from_gdt(gdt: &Gdt) -> Self {
        Self {
            limit: (Gdt::size() - 1) as u16,
            base: gdt as *const Gdt as u64,
        }
    }
}

// ============================================================================
// Per-CPU GDT Structure
// ============================================================================

/// Per-CPU GDT and TSS with interrupt stacks
#[repr(C, align(64))]
pub struct PerCpuGdt {
    /// GDT for this CPU
    pub gdt: Gdt,
    /// TSS for this CPU
    pub tss: Tss,
    /// IST1 stack (double fault)
    pub ist1_stack: [u8; DEFAULT_STACK_SIZE],
    /// IST2 stack (NMI)
    pub ist2_stack: [u8; DEFAULT_STACK_SIZE],
    /// IST3 stack (machine check)
    pub ist3_stack: [u8; DEFAULT_STACK_SIZE],
    /// IST4 stack (debug)
    pub ist4_stack: [u8; DEFAULT_STACK_SIZE],
    /// Kernel stack (RSP0)
    pub kernel_stack: [u8; DEFAULT_STACK_SIZE],
    /// CPU ID
    pub cpu_id: u32,
    /// Initialized flag
    pub initialized: bool,
}

impl PerCpuGdt {
    /// Create uninitialized per-CPU GDT
    pub const fn new() -> Self {
        Self {
            gdt: Gdt::new(),
            tss: Tss::new(),
            ist1_stack: [0; DEFAULT_STACK_SIZE],
            ist2_stack: [0; DEFAULT_STACK_SIZE],
            ist3_stack: [0; DEFAULT_STACK_SIZE],
            ist4_stack: [0; DEFAULT_STACK_SIZE],
            kernel_stack: [0; DEFAULT_STACK_SIZE],
            cpu_id: 0,
            initialized: false,
        }
    }

    /// Initialize this per-CPU GDT
    pub fn init(&mut self, cpu_id: u32) {
        self.cpu_id = cpu_id;

        // Calculate stack tops (stacks grow downward)
        let ist1_top = self.ist1_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist2_top = self.ist2_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist3_top = self.ist3_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let ist4_top = self.ist4_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;
        let kernel_top = self.kernel_stack.as_ptr() as u64 + DEFAULT_STACK_SIZE as u64;

        // Configure TSS
        let _ = self.tss.set_ist(IST_DOUBLE_FAULT, ist1_top);
        let _ = self.tss.set_ist(IST_NMI, ist2_top);
        let _ = self.tss.set_ist(IST_MACHINE_CHECK, ist3_top);
        let _ = self.tss.set_ist(IST_DEBUG, ist4_top);
        self.tss.set_rsp0(kernel_top);

        // Configure TSS entry in GDT
        let tss_addr = &self.tss as *const Tss as u64;
        self.gdt.set_tss(tss_addr);

        self.initialized = true;
    }

    /// Load this GDT and TSS on current CPU
    ///
    /// # Safety
    /// Must only be called on the CPU that owns this structure.
    pub unsafe fn load(&self) -> Result<(), GdtError> {
        if !self.initialized {
            return Err(GdtError::NotInitialized);
        }

        // Load GDT
        let gdt_ptr = GdtPtr::from_gdt(&self.gdt);
        asm!("lgdt [{}]", in(reg) &gdt_ptr, options(readonly, nostack, preserves_flags));

        // Reload segment registers
        reload_segments_internal();

        // Load TSS
        asm!("ltr {:x}", in(reg) SEL_TSS, options(nomem, nostack, preserves_flags));

        Ok(())
    }
}

// ============================================================================
// Global State
// ============================================================================

/// BSP (Bootstrap Processor) GDT
static mut BSP_GDT: PerCpuGdt = PerCpuGdt::new();

/// Per-CPU GDT array for APs
static mut AP_GDTS: [PerCpuGdt; MAX_CPUS] = {
    const INIT: PerCpuGdt = PerCpuGdt::new();
    [INIT; MAX_CPUS]
};

/// Initialization flag
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// CPU count
static CPU_COUNT: AtomicU64 = AtomicU64::new(0);

/// Statistics
static GDT_LOADS: AtomicU64 = AtomicU64::new(0);
static TSS_LOADS: AtomicU64 = AtomicU64::new(0);
static SYSCALL_SETUPS: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// Segment Register Operations
// ============================================================================

/// Reload all segment registers after GDT change
///
/// # Safety
/// Must be called immediately after loading a new GDT.
#[inline]
unsafe fn reload_segments_internal() {
    // Reload CS using far return
    asm!(
        "push {sel}",
        "lea {tmp}, [rip + 1f]",
        "push {tmp}",
        "retfq",
        "1:",
        sel = in(reg) SEL_KERNEL_CODE as u64,
        tmp = out(reg) _,
        options(preserves_flags)
    );

    // Reload data segments
    asm!(
        "mov ds, {sel:x}",
        "mov es, {sel:x}",
        "mov ss, {sel:x}",
        sel = in(reg) SEL_KERNEL_DATA as u32,
        options(nomem, nostack, preserves_flags)
    );

    // Zero FS and GS
    asm!(
        "xor eax, eax",
        "mov fs, ax",
        "mov gs, ax",
        out("eax") _,
        options(nomem, nostack)
    );
}

/// Reload segment registers (public interface)
///
/// # Safety
/// GDT must be loaded first.
pub unsafe fn reload_segments() {
    reload_segments_internal();
}

// ============================================================================
// FS/GS Base Operations
// ============================================================================

/// MSR addresses for segment bases
const MSR_FS_BASE: u32 = 0xC000_0100;
const MSR_GS_BASE: u32 = 0xC000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Set FS base register
///
/// # Safety
/// Address must point to valid memory.
#[inline]
pub unsafe fn set_fs_base(addr: u64) {
    let low = addr as u32;
    let high = (addr >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") MSR_FS_BASE,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

/// Get FS base register
#[inline]
pub unsafe fn get_fs_base() -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_FS_BASE,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Set GS base register
///
/// # Safety
/// Address must point to valid memory.
#[inline]
pub unsafe fn set_gs_base(addr: u64) {
    let low = addr as u32;
    let high = (addr >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") MSR_GS_BASE,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

/// Get GS base register
#[inline]
pub unsafe fn get_gs_base() -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_GS_BASE,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Set kernel GS base (swapped on SWAPGS)
///
/// # Safety
/// Address must point to valid per-CPU data.
#[inline]
pub unsafe fn set_kernel_gs_base(addr: u64) {
    let low = addr as u32;
    let high = (addr >> 32) as u32;
    asm!(
        "wrmsr",
        in("ecx") MSR_KERNEL_GS_BASE,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack, preserves_flags)
    );
}

/// Get kernel GS base
#[inline]
pub unsafe fn get_kernel_gs_base() -> u64 {
    let low: u32;
    let high: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_KERNEL_GS_BASE,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack, preserves_flags)
    );
    ((high as u64) << 32) | (low as u64)
}

/// Execute SWAPGS instruction
///
/// # Safety
/// Must only be called at syscall/interrupt entry/exit boundaries.
#[inline]
pub unsafe fn swapgs() {
    asm!("swapgs", options(nomem, nostack, preserves_flags));
}

// ============================================================================
// SYSCALL/SYSRET Configuration
// ============================================================================

/// MSR addresses for SYSCALL/SYSRET
const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_CSTAR: u32 = 0xC000_0083; // Compatibility mode (not used in pure 64-bit)
const MSR_SFMASK: u32 = 0xC000_0084;

/// EFER flags
const EFER_SCE: u64 = 1 << 0; // System Call Extensions

/// Default RFLAGS mask for SYSCALL
/// Clears: IF (interrupts), TF (trap), DF (direction), AC (alignment), NT (nested task)
pub const DEFAULT_SYSCALL_MASK: u64 = (1 << 9) | (1 << 8) | (1 << 10) | (1 << 18) | (1 << 14);

/// Configure SYSCALL/SYSRET MSRs
///
/// # Arguments
/// * `entry_point` - Address of syscall entry handler
/// * `rflags_mask` - RFLAGS bits to clear on SYSCALL
///
/// # Safety
/// Entry point must be a valid syscall handler.
pub unsafe fn setup_syscall(entry_point: u64, rflags_mask: u64) {
    // Enable SCE (System Call Extensions) in EFER
    let efer_lo: u32;
    let efer_hi: u32;
    asm!(
        "rdmsr",
        in("ecx") MSR_EFER,
        out("eax") efer_lo,
        out("edx") efer_hi,
        options(nomem, nostack, preserves_flags)
    );

    let efer = ((efer_hi as u64) << 32) | (efer_lo as u64);
    let new_efer = efer | EFER_SCE;

    asm!(
        "wrmsr",
        in("ecx") MSR_EFER,
        in("eax") new_efer as u32,
        in("edx") (new_efer >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    // Configure STAR register
    // [63:48] = SYSRET CS/SS base (user segments)
    // [47:32] = SYSCALL CS/SS base (kernel segments)
    //
    // SYSCALL: CS = [47:32], SS = [47:32] + 8
    // SYSRET:  CS = [63:48] + 16, SS = [63:48] + 8
    //
    // For our GDT:
    // - Kernel: CS = 0x08, SS = 0x10 → SYSCALL base = 0x08
    // - User:   CS = 0x20|3, SS = 0x18|3 → SYSRET base = 0x10
    //   (0x10 + 16 = 0x20 for CS, 0x10 + 8 = 0x18 for SS, both ORed with 3)
    let star: u64 = (0x10u64 << 48) | (0x08u64 << 32);
    asm!(
        "wrmsr",
        in("ecx") MSR_STAR,
        in("eax") star as u32,
        in("edx") (star >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    // LSTAR = syscall entry point (64-bit)
    asm!(
        "wrmsr",
        in("ecx") MSR_LSTAR,
        in("eax") entry_point as u32,
        in("edx") (entry_point >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    // SFMASK = RFLAGS bits to clear
    asm!(
        "wrmsr",
        in("ecx") MSR_SFMASK,
        in("eax") rflags_mask as u32,
        in("edx") (rflags_mask >> 32) as u32,
        options(nomem, nostack, preserves_flags)
    );

    SYSCALL_SETUPS.fetch_add(1, Ordering::Relaxed);
}

// ============================================================================
// Initialization
// ============================================================================

/// Initialize GDT for BSP (Bootstrap Processor)
///
/// Must be called early in boot sequence before interrupts are enabled.
pub fn init() -> Result<(), GdtError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(GdtError::AlreadyInitialized);
    }

    unsafe {
        BSP_GDT.init(0);
        BSP_GDT.load()?;

        GDT_LOADS.fetch_add(1, Ordering::Relaxed);
        TSS_LOADS.fetch_add(1, Ordering::Relaxed);
        CPU_COUNT.store(1, Ordering::Release);
    }

    Ok(())
}

/// Initialize GDT for an AP (Application Processor)
///
/// # Safety
/// Must be called on the target CPU.
pub unsafe fn init_ap(cpu_id: u32) -> Result<(), GdtError> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(GdtError::InvalidCpuId);
    }

    if cpu_id == 0 {
        // BSP uses BSP_GDT
        return Ok(());
    }

    let idx = cpu_id as usize - 1;
    AP_GDTS[idx].init(cpu_id);
    AP_GDTS[idx].load()?;

    GDT_LOADS.fetch_add(1, Ordering::Relaxed);
    TSS_LOADS.fetch_add(1, Ordering::Relaxed);
    CPU_COUNT.fetch_add(1, Ordering::Release);

    Ok(())
}

/// Check if GDT is initialized
#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

// ============================================================================
// Runtime Operations
// ============================================================================

/// Update kernel stack in TSS (for context switching)
///
/// # Safety
/// Stack pointer must be valid.
pub unsafe fn set_kernel_stack(cpu_id: u32, rsp: u64) -> Result<(), GdtError> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(GdtError::InvalidCpuId);
    }

    if cpu_id == 0 {
        BSP_GDT.tss.set_rsp0(rsp);
    } else {
        let idx = cpu_id as usize - 1;
        AP_GDTS[idx].tss.set_rsp0(rsp);
    }

    Ok(())
}

/// Get kernel stack from TSS
pub fn get_kernel_stack(cpu_id: u32) -> Result<u64, GdtError> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(GdtError::InvalidCpuId);
    }

    unsafe {
        if cpu_id == 0 {
            Ok(BSP_GDT.tss.rsp0())
        } else {
            let idx = cpu_id as usize - 1;
            Ok(AP_GDTS[idx].tss.rsp0())
        }
    }
}

/// Update an IST entry in TSS
///
/// # Safety
/// Stack pointer must be valid.
pub unsafe fn set_ist(cpu_id: u32, ist_index: usize, stack_top: u64) -> Result<(), GdtError> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(GdtError::InvalidCpuId);
    }

    if cpu_id == 0 {
        BSP_GDT.tss.set_ist(ist_index, stack_top)
    } else {
        let idx = cpu_id as usize - 1;
        AP_GDTS[idx].tss.set_ist(ist_index, stack_top)
    }
}

/// Get an IST entry from TSS
pub fn get_ist(cpu_id: u32, ist_index: usize) -> Result<u64, GdtError> {
    if cpu_id as usize >= MAX_CPUS {
        return Err(GdtError::InvalidCpuId);
    }

    unsafe {
        if cpu_id == 0 {
            BSP_GDT.tss.get_ist(ist_index)
        } else {
            let idx = cpu_id as usize - 1;
            AP_GDTS[idx].tss.get_ist(ist_index)
        }
    }
}

// ============================================================================
// Selectors (Public API)
// ============================================================================

/// Segment selector collection
#[derive(Clone, Copy, Debug)]
pub struct Selectors {
    /// Kernel code selector
    pub kernel_code: u16,
    /// Kernel data selector
    pub kernel_data: u16,
    /// User code selector
    pub user_code: u16,
    /// User data selector
    pub user_data: u16,
    /// TSS selector
    pub tss: u16,
}

impl Selectors {
    /// Get standard selectors
    pub const fn standard() -> Self {
        Self {
            kernel_code: SEL_KERNEL_CODE,
            kernel_data: SEL_KERNEL_DATA,
            user_code: SEL_USER_CODE,
            user_data: SEL_USER_DATA,
            tss: SEL_TSS,
        }
    }
}

/// Get selector set
pub fn selectors() -> Selectors {
    Selectors::standard()
}

// ============================================================================
// Statistics
// ============================================================================

/// GDT statistics
#[derive(Clone, Copy, Debug, Default)]
pub struct GdtStats {
    /// Number of GDT loads
    pub gdt_loads: u64,
    /// Number of TSS loads
    pub tss_loads: u64,
    /// Number of SYSCALL configurations
    pub syscall_setups: u64,
    /// Number of initialized CPUs
    pub cpu_count: u64,
    /// GDT initialized flag
    pub initialized: bool,
}

/// Get GDT statistics
pub fn get_stats() -> GdtStats {
    GdtStats {
        gdt_loads: GDT_LOADS.load(Ordering::Relaxed),
        tss_loads: TSS_LOADS.load(Ordering::Relaxed),
        syscall_setups: SYSCALL_SETUPS.load(Ordering::Relaxed),
        cpu_count: CPU_COUNT.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
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
        assert_eq!(GdtError::None.as_str(), "no error");
        assert_eq!(GdtError::NotInitialized.as_str(), "GDT not initialized");
        assert_eq!(GdtError::InvalidIstIndex.as_str(), "IST index must be 1-7");
    }

    #[test]
    fn test_selectors() {
        assert_eq!(SEL_NULL, 0x00);
        assert_eq!(SEL_KERNEL_CODE, 0x08);
        assert_eq!(SEL_KERNEL_DATA, 0x10);
        assert_eq!(SEL_USER_DATA, 0x1B); // 0x18 | 3
        assert_eq!(SEL_USER_CODE, 0x23); // 0x20 | 3
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
        // 5 GdtEntry (40 bytes) + 1 TssEntry (16 bytes) = 56 bytes
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
        assert_eq!(tss.iomap_base, TSS_SIZE as u16);
    }

    #[test]
    fn test_tss_ist_bounds() {
        let mut tss = Tss::new();

        // Index 0 should fail
        assert!(tss.set_ist(0, 0x1000).is_err());
        // Index 8 should fail
        assert!(tss.set_ist(8, 0x1000).is_err());
        // Valid indices
        assert!(tss.set_ist(1, 0x1000).is_ok());
        assert!(tss.set_ist(7, 0x7000).is_ok());

        assert_eq!(tss.get_ist(1).unwrap(), 0x1000);
        assert_eq!(tss.get_ist(7).unwrap(), 0x7000);
    }

    #[test]
    fn test_tss_rsp_bounds() {
        let mut tss = Tss::new();

        // Index 3 should fail
        assert!(tss.set_rsp(3, 0x1000).is_err());
        // Valid indices
        assert!(tss.set_rsp(0, 0x1000).is_ok());
        assert!(tss.set_rsp(2, 0x3000).is_ok());

        assert_eq!(tss.get_rsp(0).unwrap(), 0x1000);
        assert_eq!(tss.get_rsp(2).unwrap(), 0x3000);
    }

    #[test]
    fn test_syscall_selectors() {
        // Verify SYSCALL/SYSRET selector math
        let sysret_base: u16 = 0x10;
        let syscall_base: u16 = 0x08;

        // SYSCALL: CS = base, SS = base + 8
        assert_eq!(syscall_base, SEL_KERNEL_CODE);
        assert_eq!(syscall_base + 8, SEL_KERNEL_DATA);

        // SYSRET: CS = base + 16 | 3, SS = base + 8 | 3
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
}
