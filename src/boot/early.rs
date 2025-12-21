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
//! Early Boot Initialization
//!
//!
//! # Boot Sequence
//!
//! 1. BSS clearing
//! 2. Serial port initialization
//! 3. CPU structure setup (GDT, IDT, TSS)
//! 4. Memory initialization
//! 5. Interrupt setup
//! 6. Core subsystem initialization

extern crate alloc;

use core::fmt::Write;
use x86_64::instructions::port::Port;
use x86_64::structures::paging::PageTable;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::phys::AllocFlags;

// ============================================================================
// Serial Port
// ============================================================================

/// COM1 base port
const COM1: u16 = 0x3F8;

/// Initialize COM1 serial port for early diagnostics
///
/// # Safety
///
/// Writes directly to I/O ports.
pub unsafe fn init_serial() {
    let mut data = Port::<u8>::new(COM1);
    let mut ier = Port::<u8>::new(COM1 + 1);
    let mut lcr = Port::<u8>::new(COM1 + 3);
    let mut fcr = Port::<u8>::new(COM1 + 2);

    // Disable interrupts
    ier.write(0x00);

    // Enable DLAB for baud rate
    lcr.write(0x80);

    // Set baud rate divisor (115200 baud)
    data.write(0x03);
    ier.write(0x00);

    // 8N1 mode
    lcr.write(0x03);

    // Enable FIFO with 14-byte threshold
    fcr.write(0xC7);

    // Enable interrupts
    ier.write(0x01);
}

/// Serial port writer for early diagnostics
struct SerialWriter;

impl Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            unsafe {
                let mut port = Port::<u8>::new(COM1);
                // Wait for transmit buffer empty
                let mut lsr = Port::<u8>::new(COM1 + 5);
                while lsr.read() & 0x20 == 0 {}
                port.write(byte);
            }
        }
        Ok(())
    }
}

/// Print to serial port (early boot)
pub fn serial_print(args: core::fmt::Arguments) {
    let _ = SerialWriter.write_fmt(args);
}


// ============================================================================
// BSS Initialization
// ============================================================================

/// Clear the BSS section to zero
///
/// # Safety
///
/// Must be called exactly once at the start of boot before using any
/// static variables.
pub unsafe fn clear_bss() {
    extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    let start = &__bss_start as *const u8 as usize;
    let end = &__bss_end as *const u8 as usize;
    let len = end.saturating_sub(start);

    if len > 0 {
        core::ptr::write_bytes(start as *mut u8, 0, len);
    }
}

// ============================================================================
// Memory Initialization
// ============================================================================

/// UEFI memory descriptor (for boot info parsing)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    /// Memory type
    pub ty: u32,
    /// Physical start address
    pub phys_start: u64,
    /// Virtual start address
    pub virt_start: u64,
    /// Number of 4KiB pages
    pub page_count: u64,
    /// Attribute flags
    pub attribute: u64,
}

/// UEFI memory type for conventional (usable) memory
const EFI_CONVENTIONAL_MEMORY: u32 = 7;

/// Boot information from bootloader
#[repr(C)]
pub struct BootInfo {
    /// Memory map from UEFI
    pub memory_map: &'static [MemoryDescriptor],
    /// Framebuffer info (if available)
    pub framebuffer: Option<FramebufferInfo>,
    /// ACPI RSDP address
    pub rsdp_addr: Option<u64>,
    /// Kernel image offset
    pub kernel_image_offset: u64,
}

/// Framebuffer information
#[repr(C)]
pub struct FramebufferInfo {
    /// Buffer physical address
    pub buffer_addr: u64,
    /// Buffer size in bytes
    pub buffer_size: usize,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Bytes per scanline
    pub stride: u32,
}

/// Initialize memory subsystem from boot info
///
/// # Safety
///
/// Must be called exactly once during early boot with valid boot info.
pub unsafe fn init_memory(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    // Collect usable memory regions
    static mut USABLE_REGIONS: Option<heapless::Vec<crate::memory::layout::Region, 32>> = None;
    USABLE_REGIONS = Some(heapless::Vec::new());
    let regions = USABLE_REGIONS.as_mut().unwrap();

    for desc in boot_info.memory_map {
        if desc.ty == EFI_CONVENTIONAL_MEMORY {
            let _ = regions.push(crate::memory::layout::Region {
                start: desc.phys_start,
                end: desc.phys_start + desc.page_count * 4096,
                kind: crate::memory::layout::RegionKind::Usable,
            });
        }
    }

    if regions.is_empty() {
        return Err("No usable memory regions found");
    }

    // Initialize physical memory allocator
    crate::memory::phys::init(
        PhysAddr::new(regions[0].start_addr()),
        PhysAddr::new(regions[0].end_addr()),
    )
    .map_err(|_| "Failed to initialize physical memory")?;

    // Initialize virtual memory
    let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
    let l4_table = get_level_4_table(phys_offset);
    crate::memory::virt::init(PhysAddr::new(l4_table as u64))
        .map_err(|_| "Virtual memory init failed")?;

    // Set up kernel heap (8 MiB)
    const HEAP_SIZE: usize = 8 * 1024 * 1024;
    let heap_start = VirtAddr::new(0xFFFF_8800_0000_0000);

    for i in 0..(HEAP_SIZE / 4096) {
        let page = heap_start + (i * 4096) as u64;
        let frame = crate::memory::phys::alloc(AllocFlags::empty())
            .map_err(|_| "Failed to allocate heap frame")?;
        crate::memory::virt::map_page_4k(page, PhysAddr::new(frame.0), true, false, false)
            .map_err(|_| "Failed to map heap page")?;
    }

    crate::memory::heap::init().map_err(|_| "Failed to initialize heap")?;

    Ok(())
}

/// Get the level 4 page table from CR3
unsafe fn get_level_4_table(phys_offset: VirtAddr) -> *mut PageTable {
    use x86_64::registers::control::Cr3;

    let (l4_frame, _) = Cr3::read();
    let phys = l4_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    virt.as_mut_ptr()
}

// ============================================================================
// CPU Initialization
// ============================================================================

/// Read the local APIC ID for the current CPU
pub fn read_apic_id() -> u32 {
    let result = unsafe { core::arch::x86_64::__cpuid(1) };
    (result.ebx >> 24) & 0xFF
}

/// Initialize CPU structures (GDT, IDT, TSS)
///
/// # Safety
///
/// Must be called once for BSP during boot.
pub unsafe fn init_cpu_structures() {
    // Initialize GDT for BSP
    crate::arch::x86_64::gdt::init()
        .expect("Failed to initialize GDT");

    // Initialize IDT
    crate::arch::x86_64::idt::init();
}

// ============================================================================
// Interrupt Initialization
// ============================================================================

/// Initialize interrupt controllers and enable interrupts
///
/// # Safety
///
/// Must be called after CPU structures are initialized.
pub unsafe fn init_interrupts() {
    use crate::arch::x86_64::interrupt::nonos_ioapic::{IsoFlags, MadtIoApic, MadtIso, MadtNmi};

    // Initialize local APIC
    crate::arch::x86_64::interrupt::apic::init();

    // Initialize ACPI and parse MADT for IOAPIC
    if crate::arch::x86_64::acpi::init().is_ok() {
        if let Some(madt) = crate::arch::x86_64::acpi::madt::parse_madt() {
            let ioapics: alloc::vec::Vec<MadtIoApic> = madt
                .ioapics
                .iter()
                .map(|io| MadtIoApic {
                    phys_base: io.phys_base,
                    gsi_base: io.gsi_base,
                })
                .collect();

            let isos: alloc::vec::Vec<MadtIso> = madt
                .isos
                .iter()
                .map(|iso| MadtIso {
                    bus_irq: iso.bus_irq,
                    gsi: iso.gsi,
                    flags: IsoFlags::from_bits_truncate(iso.flags),
                })
                .collect();

            let nmis: alloc::vec::Vec<MadtNmi> = madt
                .nmis
                .iter()
                .map(|nmi| MadtNmi {
                    cpu: nmi.cpu,
                    lint: nmi.lint,
                    flags: IsoFlags::from_bits_truncate(nmi.flags),
                })
                .collect();

            if let Err(e) = crate::arch::x86_64::interrupt::nonos_ioapic::init(&ioapics, &isos, &nmis)
            {
                serial_print(format_args!("[BOOT] IOAPIC init failed: {}\n", e.as_str()));
            } else {
                serial_print(format_args!(
                    "[BOOT] IOAPIC initialized: {} chips, {} ISOs, {} NMIs\n",
                    ioapics.len(),
                    isos.len(),
                    nmis.len()
                ));
            }
        }
    }

    // Initialize timer
    crate::arch::x86_64::time::timer::init();

    // Enable interrupts
    x86_64::instructions::interrupts::enable();
}

// ============================================================================
// Subsystem Initialization
// ============================================================================

/// Initialize core kernel subsystems
///
/// # Safety
///
/// Must be called after memory and interrupts are initialized.
pub unsafe fn init_core_subsystems() {
    crate::log::logger::init();
    crate::log::info!("[BOOT] Logger initialized");

    crate::crypto::vault::init_vault();
    crate::log::info!("[BOOT] Crypto vault initialized");

    crate::sched::init();
    crate::log::info!("[BOOT] Scheduler initialized");

    crate::ipc::init_ipc();
    crate::log::info!("[BOOT] IPC initialized");

    crate::ui::cli::spawn();
    crate::log::info!("[BOOT] CLI spawned");
}

/// Initialize the module system
///
/// # Safety
///
/// Must be called after core subsystems are initialized.
pub unsafe fn init_module_system() {
    crate::modules::mod_loader::init_module_loader();
    crate::syscall::capabilities::init_capabilities();
    load_initial_modules();
}

/// Load initial boot modules
unsafe fn load_initial_modules() {
    let test_manifest = crate::modules::manifest::ModuleManifest {
        name: "init".into(),
        version: "1.0.0".into(),
        author: "NØNOS".into(),
        description: "Initial boot module".into(),
        capabilities: alloc::vec![
            crate::process::capabilities::Capability::CoreExec,
            crate::process::capabilities::Capability::IO,
        ],
        privacy_policy: crate::modules::manifest::PrivacyPolicy::ZeroStateOnly,
        attestation_chain: alloc::vec![],
        hash: [0; 32],
    };

    let manifest_ref = alloc::boxed::Box::leak(alloc::boxed::Box::new(test_manifest));
    let _ = crate::modules::mod_loader::verify_and_queue(manifest_ref);
}

/// Start the scheduler (never returns)
///
/// # Safety
///
/// Must be called as the final boot step.
pub unsafe fn start_scheduler() -> ! {
    crate::sched::enter()
}
