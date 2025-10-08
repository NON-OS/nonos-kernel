//! Architecture-specific implementations
//! 
//! Advanced hardware abstraction for x86_64

pub mod nonos_boot;

// Re-export for backward compatibility
pub use nonos_boot as boot;
pub mod x86_64;

// Re-export the target architecture
pub use x86_64::*;

/// Yield CPU for power management
pub fn cpu_yield() {
    unsafe {
        // Use HLT instruction to yield CPU and save power
        core::arch::asm!("hlt");
    }
}

/// Disable interrupts
pub fn disable_interrupts() {
    unsafe {
        core::arch::asm!("cli");
    }
}

/// Enable interrupts
pub fn enable_interrupts() {
    unsafe {
        core::arch::asm!("sti");
    }
}

/// Get CPU ID
pub fn get_cpu_id() -> u32 {
    // Simplified - would use CPUID in real implementation
    0
}

/// Initialize CPU features
pub fn init_cpu_features() {
    // Initialize CPU-specific features like SSE, AVX, etc.
}
