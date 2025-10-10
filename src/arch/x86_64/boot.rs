//! x86_64 Boot Entry Point

use core::arch::asm;

/// The actual entry point from bootloader
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _arch_start() -> ! {
    // Use a simple identity-mapped stack in low memory until paging is set up
    // This avoids any references to higher-half virtual addresses before VM init
    let boot_stack = 0x180000u64; // 1.5MB physical address for temporary boot stack

    asm!(
        "mov rsp, {}",
        "mov rbp, rsp",
        "call {}",
        in(reg) boot_stack,
        sym x86_64_kernel_main,
        options(noreturn)
    );
}

#[no_mangle]
unsafe extern "C" fn x86_64_kernel_main() -> ! {
    // ABSOLUTE FIRST INSTRUCTION - Show we've reached the entry point
    let vga = 0xB8000 as *mut u16;
    *vga = 0x0F4E; // 'N' - white on black
    *vga.add(1) = 0x0F4F; // 'O'
    *vga.add(2) = 0x0F4E; // 'N'
    *vga.add(3) = 0x0F4F; // 'O'
    *vga.add(4) = 0x0F53; // 'S'
    *vga.add(5) = 0x0F20; // ' '
    *vga.add(6) = 0x0F42; // 'B'
    *vga.add(7) = 0x0F4F; // 'O'
    *vga.add(8) = 0x0F4F; // 'O'
    *vga.add(9) = 0x0F54; // 'T'

    // Show boot progress
    *vga.add(80) = 0x0F49; // 'I' - second line
    *vga.add(81) = 0x0F4E; // 'N'
    *vga.add(82) = 0x0F49; // 'I'
    *vga.add(83) = 0x0F54; // 'T'
    *vga.add(84) = 0x0F2E; // '.'
    *vga.add(85) = 0x0F2E; // '.'
    *vga.add(86) = 0x0F2E; // '.'

    // Try to initialize basic systems step by step with error checking
    if init_boot_sequence() {
        // If boot sequence succeeds, transition to main kernel
        *vga.add(160) = 0x0F4F; // 'O' - third line
        *vga.add(161) = 0x0F4B; // 'K'
        *vga.add(162) = 0x0F20; // ' '
        *vga.add(163) = 0x0F2D; // '-'
        *vga.add(164) = 0x0F3E; // '>'
        *vga.add(165) = 0x0F4D; // 'M'
        *vga.add(166) = 0x0F41; // 'A'
        *vga.add(167) = 0x0F49; // 'I'
        *vga.add(168) = 0x0F4E; // 'N'

        // Jump to main kernel
        crate::kernel_main();
    } else {
        // Boot failed, show error and halt
        *vga.add(160) = 0x0C45; // 'E' - red on black (error)
        *vga.add(161) = 0x0C52; // 'R'
        *vga.add(162) = 0x0C52; // 'R'
        *vga.add(163) = 0x0C4F; // 'O'
        *vga.add(164) = 0x0C52; // 'R'

        safe_idle_loop();
    }
}

/// Initialize boot sequence with proper error handling
unsafe fn init_boot_sequence() -> bool {
    let vga = 0xB8000 as *mut u16;

    // Step 1: Initialize early VGA for debugging
    *vga.add(240) = 0x0A31; // '1' - green on black (step 1)

    // Step 2: Set up basic memory management
    *vga.add(241) = 0x0A32; // '2' - green on black (step 2)
    if !init_memory_early() {
        *vga.add(241) = 0x0C32; // '2' - red on black (failed)
        return false;
    }

    // Step 3: Initialize CPU structures (GDT/IDT)
    *vga.add(242) = 0x0A33; // '3' - green on black (step 3)
    if !init_cpu_early() {
        *vga.add(242) = 0x0C33; // '3' - red on black (failed)
        return false;
    }

    // Step 4: Enable interrupts carefully
    *vga.add(243) = 0x0A34; // '4' - green on black (step 4)
    if !init_interrupts_early() {
        *vga.add(243) = 0x0C34; // '4' - red on black (failed)
        return false;
    }

    // Step 5: Initialize basic heap
    *vga.add(244) = 0x0A35; // '5' - green on black (step 5)
    if !init_heap_early() {
        *vga.add(244) = 0x0C35; // '5' - red on black (failed)
        return false;
    }

    // All steps completed successfully
    *vga.add(245) = 0x0F4F; // 'O' - white on black
    *vga.add(246) = 0x0F4B; // 'K' - white on black

    true
}

/// Early memory initialization (minimal, no static access)
unsafe fn init_memory_early() -> bool {
    // Set up basic identity mapping and higher-half mapping
    use x86_64::registers::control::Cr3;

    // Get current page table from bootloader
    let (level4_table_frame, _) = Cr3::read();

    // Verify we have a valid page table
    if level4_table_frame.start_address().as_u64() == 0 {
        return false;
    }

    // The bootloader should have set up basic mappings
    // Just verify they work by testing a higher-half address
    let test_addr = 0xFFFF_8000_0000_0000u64;
    let test_ptr = test_addr as *const u8;

    // Try to read from higher-half - if this page faults, memory isn't set up
    // We can't easily catch page faults here, so we'll trust the bootloader for now

    true
}

/// Early CPU initialization (minimal GDT/IDT setup)
unsafe fn init_cpu_early() -> bool {
    // Create minimal GDT and IDT without accessing global statics

    // Simple GDT with just the required entries
    #[repr(C, packed)]
    struct SimpleGdt {
        null: u64,
        code: u64,
        data: u64,
    }

    static mut SIMPLE_GDT: SimpleGdt = SimpleGdt {
        null: 0,
        code: 0x00AF9A000000FFFF, // 64-bit code segment
        data: 0x00CF92000000FFFF, // 64-bit data segment
    };

    // Load the simple GDT
    use x86_64::instructions::tables;

    let gdtr = x86_64::structures::DescriptorTablePointer {
        limit: (core::mem::size_of::<SimpleGdt>() - 1) as u16,
        base: x86_64::VirtAddr::new(&SIMPLE_GDT as *const _ as u64),
    };

    tables::lgdt(&gdtr);

    // Reload segment registers
    core::arch::asm!(
        "push {code_seg}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        "mov {data_reg}, {data_seg}",
        "mov ds, {data_reg}",
        "mov es, {data_reg}",
        "mov fs, {data_reg}",
        "mov gs, {data_reg}",
        "mov ss, {data_reg}",
        code_seg = in(reg) 8u64,  // Code segment selector
        data_seg = in(reg) 16u64, // Data segment selector
        data_reg = out(reg) _,
        tmp = out(reg) _,
    );

    true
}

/// Early interrupt initialization (minimal IDT)
unsafe fn init_interrupts_early() -> bool {
    // Create minimal IDT with default handlers
    use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

    static mut SIMPLE_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

    // Set up basic exception handlers
    extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
        // Handle breakpoint interrupt - for debugging
        let rip = stack_frame.instruction_pointer.as_u64();
        crate::log::logger::log_warn!("BREAKPOINT at RIP: 0x{:x}", rip);

        // Continue execution by doing nothing - INT3 is used for debugging
    }

    /// Never-returning system halt function
    fn halt_system() -> ! {
        unsafe {
            core::arch::asm!("cli"); // Disable interrupts
            loop {
                core::arch::asm!("hlt"); // Halt forever
            }
        }
    }

    extern "x86-interrupt" fn page_fault_handler(
        stack_frame: InterruptStackFrame,
        error_code: x86_64::structures::idt::PageFaultErrorCode,
    ) {
        // Handle page fault exception
        let fault_address = x86_64::registers::control::Cr2::read();
        let rip = stack_frame.instruction_pointer.as_u64();

        crate::log::logger::log_err!(
            "PAGE FAULT at RIP: 0x{:x}\nFault Address: 0x{:x}\nError Code: {:?}",
            rip,
            fault_address.as_u64(),
            error_code
        );

        // Check if this is a recoverable page fault
        if error_code.contains(x86_64::structures::idt::PageFaultErrorCode::CAUSED_BY_WRITE) {
            // Write access fault - might be copy-on-write or heap expansion
            if let Err(_) = crate::memory::handle_page_fault(fault_address, true) {
                panic!("Unhandled write page fault at 0x{:x}", fault_address.as_u64());
            }
        } else {
            // Read access fault - might be demand paging
            if let Err(_) = crate::memory::handle_page_fault(fault_address, false) {
                panic!("Unhandled read page fault at 0x{:x}", fault_address.as_u64());
            }
        }
    }

    // TODO: Fix double fault handler type issue
    // extern "x86-interrupt" fn double_fault_wrapper(stack_frame:
    // InterruptStackFrame, error_code: u64) {
    //     crate::interrupts::handlers::double_fault_handler(stack_frame,
    // error_code);     panic!("Double fault occurred");
    // }

    SIMPLE_IDT.breakpoint.set_handler_fn(breakpoint_handler);
    // TODO: Re-enable when type issue is resolved
    // SIMPLE_IDT.double_fault.set_handler_fn(double_fault_wrapper).
    // set_stack_index(0);
    SIMPLE_IDT.page_fault.set_handler_fn(page_fault_handler);

    SIMPLE_IDT.load();

    true
}

/// Early heap initialization (basic allocator)
unsafe fn init_heap_early() -> bool {
    // NOTE: Heap initialization deferred to main kernel phase
    // Early boot phase uses static allocation only
    true
}

/// Safe idle loop that doesn't access ANY global state or Mutex variables
unsafe fn safe_idle_loop() -> ! {
    // Show we entered the idle loop successfully
    let vga = 0xB8000 as *mut u16;
    *vga.add(240) = 0x0F49; // 'I' - fourth line
    *vga.add(241) = 0x0F44; // 'D'
    *vga.add(242) = 0x0F4C; // 'L'
    *vga.add(243) = 0x0F45; // 'E'
    *vga.add(244) = 0x0F20; // ' '
    *vga.add(245) = 0x0F4C; // 'L'
    *vga.add(246) = 0x0F4F; // 'O'
    *vga.add(247) = 0x0F4F; // 'O'
    *vga.add(248) = 0x0F50; // 'P'

    // Pure CPU idle loop - no global state access
    loop {
        // Use hlt to save power
        core::arch::asm!("hlt");

        // Show we're still running by updating a counter
        static mut COUNTER: u16 = 0;
        COUNTER = COUNTER.wrapping_add(1);
        *vga.add(249) = 0x0F00 | ((COUNTER % 10) as u16 + b'0' as u16);
    }
}

// Safe memory initialization that avoids higher-half statics
unsafe fn init_memory_safe() {
    // For now, just set up basic identity mapping without accessing
    // any global static variables that might be in higher-half memory

    // The bootloader has already set up basic paging for us
    // We'll defer complex memory management until later when we can
    // safely access higher-half addresses

    // TODO: Add proper memory initialization once we resolve
    // the higher-half static variable access issue
}

// Original advanced memory initialization (currently causes Page Fault)
unsafe fn init_memory() {
    // ADVANCED N0N-OS MEMORY INITIALIZATION

    // Step 1: Set up higher-half kernel mapping FIRST
    // This ensures our static variables at higher-half addresses work
    init_kernel_address_space();

    // Step 2: Initialize physical memory allocator (now safe to access higher-half
    // statics)
    init_physical_memory();

    // Step 3: Initialize virtual memory management
    init_virtual_memory();

    // Step 4: Initialize kernel heap
    init_kernel_heap();
}

unsafe fn init_kernel_address_space() {
    use x86_64::registers::control::Cr3;
    use x86_64::structures::paging::PageTable;

    // Get current page table from bootloader
    let (level4_table_frame, _) = Cr3::read();
    let phys_offset = 0xFFFF_8000_0000_0000u64; // Higher-half mapping offset

    // Map the current page table at higher-half address
    let level4_table =
        (level4_table_frame.start_address().as_u64() + phys_offset) as *mut PageTable;

    // Ensure kernel code and data are properly mapped in higher-half
    // The bootloader should have done this, but verify/fix if needed

    // Map kernel at higher-half (0xFFFF_8000_0010_0000+)
    // This allows our static variables to be accessed
}

unsafe fn init_physical_memory() {
    // Now we can safely call phys::init_from_regions because
    // higher-half addresses work

    use crate::memory::phys;

    let regions = &[crate::memory::layout::Region {
        start: 0x100000,            // 1MB
        end: 0x100000 + 0x10000000, // 256MB for now
        kind: crate::memory::layout::RegionKind::Usable,
    }];

    // Use stack-based bitmap for early boot
    static mut EARLY_BITMAP: [core::sync::atomic::AtomicU64; 2048] = {
        const INIT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        [INIT; 2048]
    };

    phys::init_from_regions(
        regions,
        0, // node_id
        phys::ScrubPolicy::OnFree,
        |words| &mut EARLY_BITMAP[..words.min(2048)],
        None,
    );
}

unsafe fn init_virtual_memory() {
    use x86_64::registers::control::Cr3;
    let (frame, _) = Cr3::read();

    // Initialize virtual memory subsystem
    crate::memory::virt::init(frame.start_address().as_u64()).ok();
}

unsafe fn init_kernel_heap() {
    // Initialize kernel heap allocator
    crate::memory::alloc::init(crate::memory::alloc::HeapPolicy {
        zero: crate::memory::alloc::ZeroPolicy::OnFree,
        guard_large: true,
        prefer_lowmem: true,
    });
}

unsafe fn init_cpu() {
    // Simple IST allocator for early boot
    struct EarlyAllocator;

    impl crate::arch::x86_64::gdt::IstAllocator for EarlyAllocator {
        unsafe fn alloc_with_guard(&self, len: usize) -> (x86_64::VirtAddr, x86_64::VirtAddr) {
            static mut BUFFER: [u8; 0x10000] = [0; 0x10000];
            static mut OFFSET: usize = 0;

            let start = x86_64::VirtAddr::new(&BUFFER[OFFSET] as *const u8 as u64);
            OFFSET += len;
            let end = x86_64::VirtAddr::new(&BUFFER[OFFSET] as *const u8 as u64);
            (start, end)
        }

        unsafe fn free_with_guard(&self, _: x86_64::VirtAddr, _: usize) {}
    }

    let alloc = EarlyAllocator;
    crate::arch::x86_64::gdt::init_bsp(0, &alloc);
    crate::arch::x86_64::idt::init();
}

unsafe fn init_interrupts() {
    // Initialize APIC
    crate::arch::x86_64::interrupt::apic::init();

    // Initialize timer
    crate::arch::x86_64::time::timer::init();

    // Enable interrupts
    x86_64::instructions::interrupts::enable();
}

// External symbols from linker script
extern "C" {
    static __boot_stack_top: u8;
}
