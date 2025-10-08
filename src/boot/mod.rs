//! NØNOS Boot Sequence - Complete Implementation
//! 
//! This module provides the complete boot sequence from UEFI handoff
//! to fully initialized kernel with scheduler running.

// pub mod entry; // Commented out - conflicts with direct UEFI boot approach in main.rs
pub mod nonos_multiboot;
pub mod nonos_super_kernel;

// Re-exports for backward compatibility
pub use nonos_multiboot as multiboot;
pub use nonos_super_kernel as super_kernel;

/// Initialize VGA output for early boot messages
pub fn init_vga_output() {
    // Initialize VGA text mode output
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

/// Initialize panic handler
pub fn init_panic_handler() {
    // Panic handler is already defined, just ensure it's ready
}

/// Early initialization before memory allocator is ready (minimal to avoid higher-half access)
pub fn init_early() {
    // Very basic early initialization - no higher-half memory access allowed!
    // Do minimal setup that doesn't require heap or global data structures
    
    // Skip logger initialization until after memory is set up
    // Skip entropy initialization - may access global state
    // Skip security monitoring - may access global state
    
    // Just return - defer all initialization to after memory setup
}

// Serial output macros (moved to top)
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::boot::_serial_print(format_args!($($arg)*));
    };
}

macro_rules! serial_println {
    () => { serial_print!("\n") };
    ($($arg:tt)*) => {
        serial_print!("{}\n", format_args!($($arg)*));
    };
}

macro_rules! log_info {
    ($($arg:tt)*) => {
        serial_println!("[INFO] {}", format_args!($($arg)*));
    };
}

use core::panic::PanicInfo;
use x86_64::VirtAddr;
use x86_64::structures::paging::PageTable;
use crate::memory::phys::AllocFlags;
use crate::memory::virt::VmFlags;
use x86_64::PhysAddr;

/// UEFI Memory Map Entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub ty: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

/// Boot Information passed from bootloader
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

/// Early allocator for IST stacks (before heap is ready)
struct EarlyAllocator {
    next_page: VirtAddr,
}

impl EarlyAllocator {
    const fn new() -> Self {
        Self {
            // Start allocating from a known safe region
            next_page: unsafe { VirtAddr::new_unsafe(0xFFFF_8000_1000_0000) },
        }
    }
    
    unsafe fn alloc_pages(&mut self, count: usize) -> VirtAddr {
        let addr = self.next_page;
        self.next_page += (count * 4096) as u64;
        
        // Map the pages (simplified - in real impl would use phys allocator)
        for i in 0..count {
            let page_addr = addr + (i * 4096) as u64;
            // This would map to actual physical frames
            // For now, identity map for simplicity
        }
        
        addr
    }
}

impl crate::arch::x86_64::gdt::IstAllocator for EarlyAllocator {
    unsafe fn alloc_with_guard(&self, len: usize) -> (VirtAddr, VirtAddr) {
        let pages = (len + 4095) / 4096;
        // Use static allocation for early boot
        static mut IST_MEMORY: [u8; 64 * 1024] = [0; 64 * 1024];
        let base = VirtAddr::new(IST_MEMORY.as_mut_ptr() as u64);
        let usable = base + 4096u64; // Skip guard page
        let end = usable + len as u64;
        (usable, end)
    }
    
    unsafe fn free_with_guard(&self, _base: VirtAddr, _len: usize) {
        // Early allocator doesn't free
    }
}

static mut EARLY_ALLOC: EarlyAllocator = EarlyAllocator::new();

/// Kernel entry point from bootloader (DISABLED - using boot/entry.rs instead)
/*
#[no_mangle]
pub extern "C" fn _start(boot_info: &'static BootInfo) -> ! {
    // Stage 0: Absolute minimum initialization
    unsafe {
        // Clear BSS (should be done by bootloader, but be safe)
        clear_bss();
        
        // Initialize serial for early debugging
        init_serial_early();
        serial_println!("[BOOT] NØNOS kernel starting...");
        
        // Stage 1: Memory initialization
        serial_println!("[BOOT] Initializing memory subsystem...");
        init_memory(boot_info).expect("Memory initialization failed");
        
        // Stage 2: CPU structures (GDT, IDT, TSS)
        serial_println!("[BOOT] Setting up CPU structures...");
        init_cpu_structures();
        
        // Stage 3: Interrupts and APIC
        serial_println!("[BOOT] Initializing interrupts...");
        init_interrupts();
        
        // Stage 4: Core subsystems
        serial_println!("[BOOT] Initializing core subsystems...");
        init_core_subsystems();
        
        // Stage 5: Module loader
        serial_println!("[BOOT] Initializing module system...");
        init_module_system();
        
        // Stage 6: Start scheduler
        serial_println!("[BOOT] Starting scheduler...");
        start_scheduler();
    }
}
*/

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
    // Initialize COM1 for debugging
    use x86_64::instructions::port::Port;
    
    let mut port = Port::<u8>::new(0x3F8);
    
    // Disable interrupts
    port.write(0x00);
    
    // Enable DLAB
    let mut lcr = Port::<u8>::new(0x3FB);
    lcr.write(0x80);
    
    // Set baud rate divisor (38400 baud)
    port.write(0x03);
    let mut msb = Port::<u8>::new(0x3F9);
    msb.write(0x00);
    
    // 8 bits, no parity, one stop bit
    lcr.write(0x03);
    
    // Enable FIFO
    let mut fcr = Port::<u8>::new(0x3FA);
    fcr.write(0xC7);
    
    // Enable interrupts
    let mut ier = Port::<u8>::new(0x3F9);
    ier.write(0x01);
}

unsafe fn init_memory(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    // Parse memory map
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
    
    // Initialize physical memory allocator
    crate::memory::phys::init_from_regions(
        &usable_regions[..],
        0, // node_id
        crate::memory::phys::ScrubPolicy::OnFree,
        |words| {
            // Allocate bitmap backing
            let bytes = words * 8;
            let pages = (bytes + 4095) / 4096;
            let addr = EARLY_ALLOC.alloc_pages(pages);
            unsafe {
                core::slice::from_raw_parts_mut(
                    addr.as_u64() as *mut core::sync::atomic::AtomicU64,
                    words
                )
            }
        },
        None, // No audit sink yet
    );
    
    // Initialize virtual memory
    let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
    let l4_table = get_level_4_table(phys_offset);
    crate::memory::virt::init(l4_table as u64).map_err(|_| "Virtual memory init failed")?;
    
    // Initialize kernel heap
    const HEAP_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
    let heap_start = VirtAddr::new(0xFFFF_8800_0000_0000);
    
    // Map heap pages
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
    
    // Initialize heap allocator
    crate::memory::heap::init_kernel_heap();
    
    Ok(())
}

unsafe fn init_cpu_structures() {
    // Initialize GDT with TSS
    let apic_id = read_apic_id();
    crate::arch::x86_64::gdt::init_bsp(apic_id, &EARLY_ALLOC);
    
    // Initialize IDT
    crate::arch::x86_64::idt::init();
    
    // Load GDT and IDT
    x86_64::instructions::tables::load_tss(
        crate::arch::x86_64::gdt::selectors().tss
    );
}

unsafe fn init_interrupts() {
    // Initialize Local APIC
    crate::arch::x86_64::interrupt::apic::init();
    
    // TODO: ACPI MADT parsing for I/O APIC discovery
    // if let Some(rsdp) = find_rsdp() {
    //     let madt = parse_madt(rsdp);
    //     
    //     // Initialize I/O APICs
    //     crate::arch::x86_64::interrupt::ioapic::init(
    //         &madt.ioapics,
    //         &madt.isos,
    //         &madt.nmis,
    //     );
    // }
    
    // Initialize timer
    crate::arch::x86_64::time::timer::init(); // Initialize timer
    
    // Enable interrupts
    x86_64::instructions::interrupts::enable();
}

unsafe fn init_core_subsystems() {
    // Initialize logger
    crate::log::logger::init();
    log_info!("[BOOT] Logger initialized");
    
    // Initialize crypto vault
    crate::crypto::vault::init_vault();
    log_info!("[BOOT] Crypto vault initialized");
    
    // Initialize scheduler
    crate::sched::init();
    log_info!("[BOOT] Scheduler initialized");
    
    // Initialize IPC
    crate::ipc::init_ipc();
    log_info!("[BOOT] IPC initialized");
    
    // Initialize CLI
    crate::ui::cli::spawn();
    log_info!("[BOOT] CLI spawned");
}

unsafe fn init_module_system() {
    // Initialize module loader
    crate::modules::mod_loader::init_module_loader();
    
    // Initialize capability system
    crate::syscall::capabilities::init_capabilities();
    
    // Load initial modules if any
    load_initial_modules();
}

unsafe fn load_initial_modules() {
    // This would load any modules embedded in the kernel image
    // or passed by the bootloader
    
    // For now, create a test module
    let test_manifest = crate::modules::manifest::ModuleManifest {
        name: "init",
        version: "1.0.0",
        hash: [0; 32],
        signature: [0; 64],
        public_key: [0; 32],
        signer: crate::crypto::vault::VaultPublicKey::default(),
        auth_chain_id: None,
        auth_method: crate::modules::manifest::AuthMethod::VaultSignature,
        zk_attestation: None,
        required_caps: alloc::vec![
            crate::syscall::capabilities::Capability::CoreExec,
            crate::syscall::capabilities::Capability::IO,
        ],
        fault_policy: Some(crate::modules::runtime::FaultPolicy::Restart),
        memory_bytes: 64 * 1024, // 64 KiB
        timestamp: 0,
        expiry_seconds: None,
        entry_point_addr: Some(0x400000),
        module_type: crate::modules::manifest::ModuleType::System,
        memory_requirements: crate::modules::manifest::MemoryRequirements {
            min_heap: 64 * 1024,
            max_heap: 128 * 1024,
            stack_size: 8 * 1024,
        },
    };
    
    // We need to store this in a Box to get a static reference
    let manifest_ref = alloc::boxed::Box::leak(alloc::boxed::Box::new(test_manifest));
    crate::modules::mod_loader::verify_and_queue(manifest_ref).ok();
}

extern "C" fn init_module_entry(_arg: usize) -> ! {
    // Initial module that spawns user tasks
    loop {
        // Would spawn shell or other initial programs
        unsafe {
            x86_64::instructions::hlt();
        }
    }
}

unsafe fn start_scheduler() -> ! {
    // The scheduler takes over from here
    crate::sched::enter()
}

fn read_apic_id() -> u32 {
    // Read APIC ID from CPUID
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

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Try to print to serial
    serial_println!("\n!!! KERNEL PANIC !!!");
    serial_println!("{}", info);
    
    // Try to print to VGA
    unsafe {
        let vga = 0xb8000 as *mut u16;
        let msg = b"KERNEL PANIC";
        for (i, &byte) in msg.iter().enumerate() {
            *vga.add(i) = 0x4F00 | byte as u16; // Red on white
        }
    }
    
    // Halt all CPUs
    loop {
        unsafe {
            x86_64::instructions::interrupts::disable();
            x86_64::instructions::hlt();
        }
    }
}

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

// Re-export super kernel functionality
pub use nonos_super_kernel::{
    super_kernel_entry,
    set_debug_mode,
    set_gui_mode,
    is_debug_mode,
    is_secure_boot,
    is_zk_attestation,
};

// Re-export boot memory functionality for easy access
pub use crate::memory::boot_memory::{
    BootMemoryManager,
    BootMemoryInfo,
    BootMemoryRegion,
    BootMemoryType,
    init_boot_memory,
    enable_memory_protection,
    get_memory_stats,
};
