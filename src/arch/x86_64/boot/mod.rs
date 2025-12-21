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
// NØNOS x86_64 Boot Module                                                                  │
// Boot Flow:                                                            
// 1. Entry (_arch_start) - Stack setup                           
// 2. Early diagnostics - VGA/Serial                            
// 3. CPU detection - Features, vendor, model                 
// 4. Feature validation - SSE, long mode                     
// 5. GDT/TSS initialization - Segments, IST stacks           
// 6. IDT initialization - Exception handlers                    
// 7. SSE/AVX enablement - FPU state                            
// 8. Memory validation - Page tables, higher half              
// 9. Transfer to kernel_main                                     

pub mod nonos_boot;

// ============================================================================
// Error Types
// ============================================================================

pub use nonos_boot::BootError;

// ============================================================================
// Enumerations
// ============================================================================

pub use nonos_boot::BootStage;

// ============================================================================
// Constants
// ============================================================================

pub use nonos_boot::KERNEL_CS;
pub use nonos_boot::KERNEL_DS;
pub use nonos_boot::USER_CS;
pub use nonos_boot::USER_DS;
pub use nonos_boot::TSS_SEL;

// ============================================================================
// Structures
// ============================================================================

pub use nonos_boot::CpuFeatures;
pub use nonos_boot::Tss;
pub use nonos_boot::InterruptFrame;
pub use nonos_boot::ExceptionContext;
pub use nonos_boot::BootStats;

// ============================================================================
// Boot Status
// ============================================================================

/// Get current boot stage
#[inline]
pub fn boot_stage() -> BootStage {
    nonos_boot::boot_stage()
}

/// Get boot error
#[inline]
pub fn boot_error() -> BootError {
    nonos_boot::boot_error()
}

/// Check if boot is complete
#[inline]
pub fn is_boot_complete() -> bool {
    nonos_boot::is_boot_complete()
}

/// Get boot TSC timestamp
#[inline]
pub fn boot_tsc() -> u64 {
    nonos_boot::boot_tsc()
}

// ============================================================================
// CPU Information
// ============================================================================

/// Get CPU features
#[inline]
pub fn cpu_features() -> CpuFeatures {
    nonos_boot::cpu_features()
}

/// Get CPU family
#[inline]
pub fn cpu_family() -> u8 {
    nonos_boot::cpu_family()
}

/// Get CPU model
#[inline]
pub fn cpu_model() -> u8 {
    nonos_boot::cpu_model()
}

/// Get CPU stepping
#[inline]
pub fn cpu_stepping() -> u8 {
    nonos_boot::cpu_stepping()
}

// ============================================================================
// Memory Information
// ============================================================================

/// Get kernel stack pointer
#[inline]
pub fn kernel_stack() -> u64 {
    nonos_boot::kernel_stack()
}

// ============================================================================
// Statistics
// ============================================================================

/// Get exception count
#[inline]
pub fn exception_count() -> u64 {
    nonos_boot::exception_count()
}

/// Increment exception count (called by exception handlers)
#[inline]
pub fn increment_exception_count() {
    nonos_boot::increment_exception_count()
}

/// Get boot statistics
#[inline]
pub fn get_stats() -> BootStats {
    nonos_boot::get_stats()
}
