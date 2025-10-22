//! NØNOS Boot Sequence 

pub mod nonos_multiboot;

// Re-exports for backward compatibility
pub use nonos_multiboot as multiboot;

/// Initialize VGA output for early boot messages
pub fn init_vga_output() {
    unsafe {
        let vga = 0xb8000 as *mut u8;
        // Clear screen
        for i in 0..80*25 {
            let offset = i * 2;
            *vga.add(offset) = b' ';
            *vga.add(offset + 1) = 0x07; // Light gray on black
        }
        // Print boot header
        let header = b"N0N-OS Kernel Initializing...";
        for (i, &byte) in header.iter().enumerate() {
            let offset = i * 2;
            *vga.add(offset) = byte;
            *vga.add(offset + 1) = 0x0F; // White on black
        }
    }
}

/// Confirm panic handler is set up for the boot phase
pub fn init_panic_handler() {
    // Panic handler is defined elsewhere, just ensure linkage
}

/// Minimal early init before memory allocator is ready
pub fn init_early() {
    // No heap, no global data allowed here
    // Logger/entropy/security deferred until after memory setup
}

// Serial output macros for early boot diagnostics
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::boot::_serial_print(format_args!($($arg)*));
    };
}
macro_rules! serial_println {
    () => { serial_print!("\n") };
    ($($arg:tt)*) => { serial_print!("{}\n", format_args!($($arg)*)); };
}
// log_info macro defined in log module

use core::panic::PanicInfo;
use x86_64::VirtAddr;
use x86_64::structures::paging::PageTable;
use crate::memory::phys::AllocFlags;
use crate::memory::virt::VmFlags;
use x86_64::PhysAddr;

// --- UEFI and Bootloader Structures ---
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub ty: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

#[repr(C)]
pub struct BootInfo {
    pub memory_map: &'static [MemoryDescriptor],
    pub framebuffer: Option<FramebufferInfo>,
    pub rsdp_addr: Option<u64>,
    pub kernel_image_offset: u64,
}

#[repr(C)]
pub struct FramebufferInfo {
    pub buffer_addr: u64,
    pub buffer_size: usize,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

// --- Early Allocator for IST Stacks ---
struct EarlyAllocator {
    next_page: VirtAddr,
}
impl EarlyAllocator {
    const fn new() -> Self {
        Self {
            next_page: unsafe { VirtAddr::new_unsafe(0xFFFF_8000_1000_0000) },
        }
    }
    unsafe fn alloc_pages(&mut self, count: usize) -> VirtAddr {
        let addr = self.next_page;
        self.next_page += (count * 4096) as u64;
        addr
    }
}
impl crate::arch::x86_64::gdt::IstAllocator for EarlyAllocator {
    unsafe fn alloc_with_guard(&self, len: usize) -> (VirtAddr, VirtAddr) {
        let pages = (len + 4095) / 4096;
        static mut IST_MEMORY: [u8; 64 * 1024] = [0; 64 * 1024];
        let base = VirtAddr::new(IST_MEMORY.as_mut_ptr() as u64);
        let usable = base + 4096u64; // Guard page
        let end = usable + len as u64;
        (usable, end)
    }
    unsafe fn free_with_guard(&self, _base: VirtAddr, _len: usize) {
        // Early allocator: no free
    }
}
static mut EARLY_ALLOC: EarlyAllocator = EarlyAllocator::new();

// --- Kernel Entry Point (Disabled, migrated to entry.rs) ---

// --- Early Hardware Routines ---
unsafe fn clear_bss() {
    extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }
    let bss_start = &__bss_start as *const u8 as usize;
    let bss_end = &__bss_end as *const u8 as usize;
    let bss_len = bss_end - bss_start;
    core::ptr::write_bytes(bss_start as *mut u8, 0, bss_len);
}

unsafe fn init_serial_early() {
    use x86_64::instructions::port::Port;
    let mut port = Port::<u8>::new(0x3F8);
    port.write(0x00); // Disable interrupts
    let mut lcr = Port::<u8>::new(0x3FB);
    lcr.write(0x80); // Enable DLAB
    port.write(0x03); // Baud rate divisor
    let mut msb = Port::<u8>::new(0x3F9);
    msb.write(0x00);
    lcr.write(0x03); // 8N1
    let mut fcr = Port::<u8>::new(0x3FA);
    fcr.write(0xC7); // Enable FIFO
    let mut ier = Port::<u8>::new(0x3F9);
    ier.write(0x01); // Enable interrupts
}

unsafe fn init_memory(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    static mut USABLE_REGIONS: Option<heapless::Vec::<crate::memory::layout::Region, 32>> = None;
    USABLE_REGIONS = Some(heapless::Vec::new());
    let usable_regions = USABLE_REGIONS.as_mut().unwrap();

    for desc in boot_info.memory_map {
        if desc.ty == 7 { // EFI_CONVENTIONAL_MEMORY
            let _ = usable_regions.push(crate::memory::layout::Region {
                start: desc.phys_start,
                end: desc.phys_start + desc.page_count * 4096,
                kind: crate::memory::layout::RegionKind::Usable,
            });
        }
    }

    crate::memory::phys::init_from_regions(
        &usable_regions[..], 0,
        crate::memory::phys::ScrubPolicy::OnFree,
        |words| {
            let bytes = words * 8;
            let pages = (bytes + 4095) / 4096;
            let addr = EARLY_ALLOC.alloc_pages(pages);
            unsafe {
                core::slice::from_raw_parts_mut(
                    addr.as_u64() as *mut core::sync::atomic::AtomicU64, words
                )
            }
        },
        None,
    );

    let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
    let l4_table = get_level_4_table(phys_offset);
    crate::memory::virt::init(l4_table as u64).map_err(|_| "Virtual memory init failed")?;

    const HEAP_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
    let heap_start = VirtAddr::new(0xFFFF_8800_0000_0000);
    for i in 0..(HEAP_SIZE / 4096) {
        let page = heap_start + (i * 4096) as u64;
        let frame = crate::memory::phys::alloc(AllocFlags::empty())
            .expect("Failed to allocate heap frame");
        crate::memory::virt::map4k_at(
            page,
            PhysAddr::new(frame.0),
            VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL,
        ).map_err(|_| "Failed to map heap page")?;
    }
    crate::memory::heap::init_kernel_heap();
    Ok(())
}

unsafe fn init_cpu_structures() {
    let apic_id = read_apic_id();
    crate::arch::x86_64::gdt::init_bsp(apic_id, &EARLY_ALLOC);
    crate::arch::x86_64::idt::init();
    x86_64::instructions::tables::load_tss(
        crate::arch::x86_64::gdt::selectors().tss
    );
}

unsafe fn init_interrupts() {
    crate::arch::x86_64::interrupt::apic::init();
    // TODO: ACPI MADT parsing for IOAPIC
    crate::arch::x86_64::time::timer::init();
    x86_64::instructions::interrupts::enable();
}

unsafe fn init_core_subsystems() {
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

unsafe fn init_module_system() {
    crate::modules::mod_loader::init_module_loader();
    crate::syscall::capabilities::init_capabilities();
    load_initial_modules();
}

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
    crate::modules::mod_loader::verify_and_queue(manifest_ref).ok();
}

extern "C" fn init_module_entry(_arg: usize) -> ! {
    loop {
        unsafe { x86_64::instructions::hlt(); }
    }
}

unsafe fn start_scheduler() -> ! {
    crate::sched::enter()
}

fn read_apic_id() -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 1",
            "cpuid",
            "shr ebx, 24",
            "mov {0:e}, ebx",
            out(reg) result,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
        );
    }
    result
}

unsafe fn get_level_4_table(phys_offset: VirtAddr) -> *mut PageTable {
    use x86_64::registers::control::Cr3;
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    virt.as_mut_ptr()
}

/// Panic handler for boot phase
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("\n!!! KERNEL PANIC !!!");
    serial_println!("{}", info);
    unsafe {
        let vga = 0xb8000 as *mut u16;
        let msg = b"KERNEL PANIC";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.add(i) = 0x4F00 | byte as u16;
        }
    }
    loop {
        unsafe {
            x86_64::instructions::interrupts::disable();
            x86_64::instructions::hlt();
        }
    }
}

/// Serial print for early diagnostics
pub fn _serial_print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::port::Port;
    struct SerialPort;
    impl Write for SerialPort {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for byte in s.bytes() {
                unsafe {
                    let mut port = Port::<u8>::new(0x3F8);
                    port.write(byte);
                }
            }
            Ok(())
        }
    }
    let _ = SerialPort.write_fmt(args);
}

// Re-export boot memory interfaces for convenience (currently unused)
/*
pub use crate::memory::boot_memory::{
    BootMemoryManager,
    BootMemoryInfo,
    BootMemoryRegion,
    BootMemoryType,
    init_boot_memory,
    enable_memory_protection,
    get_memory_stats,
};
*/
