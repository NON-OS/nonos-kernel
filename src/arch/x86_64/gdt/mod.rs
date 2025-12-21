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
// NØNOS x86_64 GDT Module
//
// The Global Descriptor Table (GDT) and Task State Segment (TSS)
// for x86_64 long mode.
//
// Architecture:
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                             GDT Module                                  │
// ├─────────────────────────────────────────────────────────────────────────┤
// │                                                                         │
// │   ┌─────────────────────────────────────────────────────────────────┐   │
// │   │                         nonos_gdt.rs                            │   │
// │   │                                                                 │   │
// │   │  GDT/TSS Structures    Segment Operations    SYSCALL/SYSRET     │   │
// │   │  ─────────────────    ──────────────────    ────────────────    │   │
// │   │  GdtEntry             reload_segments()     setup_syscall()     │   │
// │   │  TssEntry             set_kernel_stack()    STAR/LSTAR/SFMASK   │   │
// │   │  Tss                  set_ist()                                 │   │
// │   │  Gdt                                        FS/GS Base          │   │
// │   │  PerCpuGdt            Initialization        ───────────         │   │
// │   │                       ──────────────        set_fs_base()       │   │
// │   │  Selectors            init()                set_gs_base()       │   │
// │   │  GdtStats             init_ap()             swapgs()            │   │
// │   │  GdtError             is_initialized()                          │   │
// │   └─────────────────────────────────────────────────────────────────┘   │
// │                                                                         │
// │   Usage:                                                                │
// │   ┌─────────────────────────────────────────────────────────────────┐   │
// │   │  // Initialize GDT (BSP)                                        │   │
// │   │  gdt::init()?;                                                  │   │
// │   │                                                                 │   │
// │   │  // Initialize GDT (AP)                                         │   │
// │   │  unsafe { gdt::init_ap(cpu_id)?; }                              │   │
// │   │                                                                 │   │
// │   │  // Update kernel stack for context switching                   │   │
// │   │  unsafe { gdt::set_kernel_stack(cpu_id, rsp)?; }                │   │
// │   │                                                                 │   │
// │   │  // Configure SYSCALL                                           │   │
// │   │  unsafe { gdt::setup_syscall(entry, gdt::DEFAULT_SYSCALL_MASK); │   │
// │   └─────────────────────────────────────────────────────────────────┘   │
// │                                                                         │
// └─────────────────────────────────────────────────────────────────────────┘

pub mod nonos_gdt;

// ============================================================================
// Error Types
// ============================================================================

pub use nonos_gdt::GdtError;

// ============================================================================
// Constants
// ============================================================================

pub use nonos_gdt::MAX_CPUS;
pub use nonos_gdt::TSS_SIZE;
pub use nonos_gdt::IST_COUNT;
pub use nonos_gdt::DEFAULT_STACK_SIZE;
pub use nonos_gdt::IOPB_SIZE;

// ============================================================================
// Segment Selectors
// ============================================================================

pub use nonos_gdt::SEL_NULL;
pub use nonos_gdt::SEL_KERNEL_CODE;
pub use nonos_gdt::SEL_KERNEL_DATA;
pub use nonos_gdt::SEL_USER_CODE;
pub use nonos_gdt::SEL_USER_DATA;
pub use nonos_gdt::SEL_TSS;
pub use nonos_gdt::SEL_KERNEL_CODE_RAW;
pub use nonos_gdt::SEL_KERNEL_DATA_RAW;
pub use nonos_gdt::SEL_USER_CODE_RAW;
pub use nonos_gdt::SEL_USER_DATA_RAW;

// ============================================================================
// IST Indices
// ============================================================================

pub use nonos_gdt::IST_DOUBLE_FAULT;
pub use nonos_gdt::IST_NMI;
pub use nonos_gdt::IST_MACHINE_CHECK;
pub use nonos_gdt::IST_DEBUG;
pub use nonos_gdt::IST_PAGE_FAULT;
pub use nonos_gdt::IST_GP;

// ============================================================================
// Structures
// ============================================================================

pub use nonos_gdt::GdtEntry;
pub use nonos_gdt::TssEntry;
pub use nonos_gdt::Tss;
pub use nonos_gdt::Gdt;
pub use nonos_gdt::GdtPtr;
pub use nonos_gdt::PerCpuGdt;
pub use nonos_gdt::Selectors;
pub use nonos_gdt::GdtStats;

// ============================================================================
// SYSCALL Configuration
// ============================================================================

pub use nonos_gdt::DEFAULT_SYSCALL_MASK;

// ============================================================================
// Initialization
// ============================================================================

/// Initialize GDT for BSP (Bootstrap Processor)
#[inline]
pub fn init() -> Result<(), GdtError> {
    nonos_gdt::init()
}

/// Initialize GDT for an AP (Application Processor)
///
/// # Safety
/// Must be called on the target CPU.
#[inline]
pub unsafe fn init_ap(cpu_id: u32) -> Result<(), GdtError> {
    nonos_gdt::init_ap(cpu_id)
}

/// Check if GDT is initialized
#[inline]
pub fn is_initialized() -> bool {
    nonos_gdt::is_initialized()
}

// ============================================================================
// Segment Operations
// ============================================================================

/// Reload segment registers
///
/// # Safety
/// GDT must be loaded first.
#[inline]
pub unsafe fn reload_segments() {
    nonos_gdt::reload_segments()
}

/// Get selector set
#[inline]
pub fn selectors() -> Selectors {
    nonos_gdt::selectors()
}

// ============================================================================
// TSS Operations
// ============================================================================

/// Update kernel stack in TSS
///
/// # Safety
/// Stack pointer must be valid.
#[inline]
pub unsafe fn set_kernel_stack(cpu_id: u32, rsp: u64) -> Result<(), GdtError> {
    nonos_gdt::set_kernel_stack(cpu_id, rsp)
}

/// Get kernel stack from TSS
#[inline]
pub fn get_kernel_stack(cpu_id: u32) -> Result<u64, GdtError> {
    nonos_gdt::get_kernel_stack(cpu_id)
}

/// Update an IST entry in TSS
///
/// # Safety
/// Stack pointer must be valid.
#[inline]
pub unsafe fn set_ist(cpu_id: u32, ist_index: usize, stack_top: u64) -> Result<(), GdtError> {
    nonos_gdt::set_ist(cpu_id, ist_index, stack_top)
}

/// Get an IST entry from TSS
#[inline]
pub fn get_ist(cpu_id: u32, ist_index: usize) -> Result<u64, GdtError> {
    nonos_gdt::get_ist(cpu_id, ist_index)
}

// ============================================================================
// FS/GS Base Operations
// ============================================================================

/// Set FS base register
///
/// # Safety
/// Address must point to valid memory.
#[inline]
pub unsafe fn set_fs_base(addr: u64) {
    nonos_gdt::set_fs_base(addr)
}

/// Get FS base register
#[inline]
pub unsafe fn get_fs_base() -> u64 {
    nonos_gdt::get_fs_base()
}

/// Set GS base register
///
/// # Safety
/// Address must point to valid memory.
#[inline]
pub unsafe fn set_gs_base(addr: u64) {
    nonos_gdt::set_gs_base(addr)
}

/// Get GS base register
#[inline]
pub unsafe fn get_gs_base() -> u64 {
    nonos_gdt::get_gs_base()
}

/// Set kernel GS base (swapped on SWAPGS)
///
/// # Safety
/// Address must point to valid per-CPU data.
#[inline]
pub unsafe fn set_kernel_gs_base(addr: u64) {
    nonos_gdt::set_kernel_gs_base(addr)
}

/// Get kernel GS base
#[inline]
pub unsafe fn get_kernel_gs_base() -> u64 {
    nonos_gdt::get_kernel_gs_base()
}

/// Execute SWAPGS instruction
///
/// # Safety
/// Must only be called at syscall/interrupt entry/exit boundaries.
#[inline]
pub unsafe fn swapgs() {
    nonos_gdt::swapgs()
}

// ============================================================================
// SYSCALL/SYSRET Configuration
// ============================================================================

/// Configure SYSCALL/SYSRET MSRs
///
/// # Safety
/// Entry point must be a valid syscall handler.
#[inline]
pub unsafe fn setup_syscall(entry_point: u64, rflags_mask: u64) {
    nonos_gdt::setup_syscall(entry_point, rflags_mask)
}

// ============================================================================
// Statistics
// ============================================================================

/// Get GDT statistics
#[inline]
pub fn get_stats() -> GdtStats {
    nonos_gdt::get_stats()
}
