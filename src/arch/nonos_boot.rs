//! NØNOS-Boot Interface

use crate::log_info;
use crate::arch::nonos_cpu;
use crate::arch::nonos_gdt;
use crate::arch::nonos_idt;
use crate::arch::nonos_acpi;
use crate::arch::nonos_multiboot;
use crate::arch::nonos_serial;
use crate::arch::nonos_pci;

/// Performs early boot initialization in a platform-neutral manner.
/// Called first before any other subsystem.
pub fn init_early() {
    // Initialize logger for diagnostics from the earliest stage.
    crate::log::init_logger();
    log_info!("Logger initialized.");

    // Initialize CPU features (SSE, AVX, etc.), disables interrupts until setup is complete.
    nonos_cpu::init_features();
    log_info!("CPU features initialized.");

    // Setup GDT (Global Descriptor Table) for segmentation and task state.
    nonos_gdt::init();
    log_info!("GDT initialized.");

    // Setup IDT (Interrupt Descriptor Table) for exception and interrupt handling.
    nonos_idt::init();
    log_info!("IDT initialized.");

    // Parse ACPI tables for platform information and hardware enumeration.
    nonos_acpi::init();
    log_info!("ACPI tables parsed.");

    // Parse and validate multiboot information from bootloader.
    nonos_multiboot::init();
    log_info!("Multiboot info parsed.");

    // Initialize serial port for early kernel debug output.
    nonos_serial::init();
    log_info!("Serial port initialized.");

    // Setup PCI bus scanning for device enumeration.
    nonos_pci::init();
    log_info!("PCI bus scanned.");

    log_info!("Early boot initialization completed.");
}
