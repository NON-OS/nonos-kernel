//! Architecture-specific implementations

pub mod nonos_boot;
pub mod nonos_acpi;
pub mod nonos_cpu;
pub mod nonos_gdt;
pub mod nonos_gdt_simple;
pub mod nonos_idt;
pub mod nonos_idt_simple;
pub mod nonos_multiboot;
pub mod nonos_pci;
pub mod nonos_serial;
pub mod nonos_smm;
pub mod nonos_syscall;
pub mod nonos_uefi;
pub mod nonos_vga;
pub mod time;
pub mod interrupt;
pub mod keyboard;
pub mod x86_64;

pub use nonos_boot as boot;
pub use nonos_acpi as acpi;
pub use nonos_cpu as cpu;
pub use nonos_gdt as gdt;
pub use nonos_gdt_simple as gdt_simple;
pub use nonos_idt as idt;
pub use nonos_idt_simple as idt_simple;
pub use nonos_multiboot as multiboot;
pub use nonos_pci as pci;
pub use nonos_serial as serial;
pub use nonos_smm as smm;
pub use nonos_syscall as syscall;
pub use nonos_uefi as uefi;
pub use nonos_vga as vga;
pub use time::*;
pub use interrupt::*;
pub use keyboard::*;
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
    // Use CPUID for real multi-core support in future
    0
}

pub fn init_cpu_features() {
    // Extend for SSE, AVX, virtualization, etc.
}
