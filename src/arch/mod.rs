//! Architecture-specific implementations

pub mod nonos_boot;
pub mod x86_64;

pub use nonos_boot as boot;
pub use x86_64::*;

/// Yield CPU for power management
pub fn cpu_yield() {
    unsafe { core::arch::asm!("hlt"); }
}

/// Disable interrupts
pub fn disable_interrupts() {
    unsafe { core::arch::asm!("cli"); }
}

/// Enable interrupts
pub fn enable_interrupts() {
    unsafe { core::arch::asm!("sti"); }
}

/// Get CPU ID
pub fn get_cpu_id() -> u32 {
    // Use CPUID for multi-core support in future
    0
}

pub fn init_cpu_features() {
    // Extend for SSE, AVX, virtualization, etc.
}
