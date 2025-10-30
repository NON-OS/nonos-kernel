//! Boot sequence for NON-OS kernel on x86_64,hardware integration and error reporting.

use core::arch::asm;

/// The actual entry point from bootloader
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _arch_start() -> ! {
    // Use a simple identity-mapped stack in low memory until paging is set up
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

/// The main entry for kernel execution after boot stack is set.
#[no_mangle]
unsafe extern "C" fn x86_64_kernel_main() -> ! {
    // Direct VGA output for boot diagnostics.
    let vga = 0xb8000 as *mut u16;
    *vga = 0x0F4E; // 'N'
    *vga.add(1) = 0x0F4F; // 'O'
    *vga.add(2) = 0x0F4E; // 'N'
    *vga.add(3) = 0x0F4F; // 'O'
    *vga.add(4) = 0x0F53; // 'S'
    *vga.add(5) = 0x0F20; // ' '
    *vga.add(6) = 0x0F42; // 'B'
    *vga.add(7) = 0x0F4F; // 'O'
    *vga.add(8) = 0x0F4F; // 'O'
    *vga.add(9) = 0x0F54; // 'T'

    // Second line: INIT...
    *vga.add(80) = 0x0F49; // 'I'
    *vga.add(81) = 0x0F4E; // 'N'
    *vga.add(82) = 0x0F49; // 'I'
    *vga.add(83) = 0x0F54; // 'T'
    *vga.add(84) = 0x0F2E; // '.'
    *vga.add(85) = 0x0F2E; // '.'
    *vga.add(86) = 0x0F2E; // '.'

    // Step-by-step boot diagnostics
    let boot_ok = init_boot_sequence();
    if boot_ok {
        *vga.add(160) = 0x0F4F; // 'O'
        *vga.add(161) = 0x0F4B; // 'K'
        *vga.add(162) = 0x0F20; // ' '
        *vga.add(163) = 0x0F2D; // '-'
        *vga.add(164) = 0x0F3E; // '>'
        *vga.add(165) = 0x0F4D; // 'M'
        *vga.add(166) = 0x0F41; // 'A'
        *vga.add(167) = 0x0F49; // 'I'
        *vga.add(168) = 0x0F4E; // 'N'
        crate::kernel_main();
    } else {
        *vga.add(160) = 0x0C45; // 'E'
        *vga.add(161) = 0x0C52; // 'R'
        *vga.add(162) = 0x0C52; // 'R'
        *vga.add(163) = 0x0C4F; // 'O'
        *vga.add(164) = 0x0C52; // 'R'
        safe_idle_loop();
    }
}

/// Full boot sequence: memory, cpu, interrupts, heap. Returns true if all succeed.
unsafe fn init_boot_sequence() -> bool {
    let vga = 0xb8000 as *mut u16;

    // Step 1: Early VGA - always succeeds
    *vga.add(240) = 0x0A31; // '1'
    // Step 2: Basic memory management
    *vga.add(241) = 0x0A32; // '2'
    if !init_memory_early() {
        *vga.add(241) = 0x0C32; // '2' red
        return false;
    }
    // Step 3: CPU structures (GDT/IDT)
    *vga.add(242) = 0x0A33; // '3'
    if !init_cpu_early() {
        *vga.add(242) = 0x0C33;
        return false;
    }
    // Step 4: Enable interrupts
    *vga.add(243) = 0x0A34; // '4'
    if !init_interrupts_early() {
        *vga.add(243) = 0x0C34;
        return false;
    }
    // Step 5: Heap
    *vga.add(244) = 0x0A35; // '5'
    if !init_heap_early() {
        *vga.add(244) = 0x0C35;
        return false;
    }
    *vga.add(245) = 0x0F4F; // 'O'
    *vga.add(246) = 0x0F4B; // 'K'
    true
}

/// Early memory initialization: verify bootloader paging and higher-half access.
unsafe fn init_memory_early() -> bool {
    use x86_64::registers::control::Cr3;
    let (level4_table_frame, _) = Cr3::read();
    if level4_table_frame.start_address().as_u64() == 0 { return false; }
    let test_addr = 0xFFFF_8000_0000_0000u64;
    let test_ptr = test_addr as *const u8;
    let _ = core::ptr::read_volatile(test_ptr); // Try reading; if page faults, not mapped.
    true
}

/// Early CPU initialization: minimal GDT/IDT setup, real segment reload.
unsafe fn init_cpu_early() -> bool {
    #[repr(C, packed)]
    struct SimpleGdt { null: u64, code: u64, data: u64 }
    static mut SIMPLE_GDT: SimpleGdt = SimpleGdt {
        null: 0,
        code: 0x00AF9A000000FFFF,
        data: 0x00CF92000000FFFF,
    };
    use x86_64::instructions::tables;
    let gdtr = x86_64::structures::DescriptorTablePointer {
        limit: (core::mem::size_of::<SimpleGdt>() - 1) as u16,
        base: x86_64::VirtAddr::new(&SIMPLE_GDT as *const _ as u64),
    };
    tables::lgdt(&gdtr);
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
        code_seg = in(reg) 8u64,
        data_seg = in(reg) 16u64,
        data_reg = out(reg) _,
        tmp = out(reg) _,
    );
    true
}

/// Early interrupt initialization: load minimal IDT with working handlers.
unsafe fn init_interrupts_early() -> bool {
    use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
    static mut SIMPLE_IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

    extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
        let rip = stack_frame.instruction_pointer.as_u64();
        crate::log_warn!("BREAKPOINT at RIP: 0x{:x}", rip);
    }
    extern "x86-interrupt" fn page_fault_handler(stack_frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
        let fault_address = x86_64::registers::control::Cr2::read();
        let rip = stack_frame.instruction_pointer.as_u64();
        crate::log::logger::log_err!(
            "PAGE FAULT at RIP: 0x{:x}, Fault Address: 0x{:x}, Error Code: {:?}",
            rip, fault_address.as_u64(), error_code
        );
        if error_code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            crate::memory::virt::handle_page_fault(fault_address, error_code.bits()).unwrap();
        } else {
            crate::memory::virt::handle_page_fault(fault_address, error_code.bits()).unwrap();
        }
    }
    SIMPLE_IDT.breakpoint.set_handler_fn(breakpoint_handler);
    SIMPLE_IDT.page_fault.set_handler_fn(page_fault_handler);
    SIMPLE_IDT.load();
    true
}

/// Early heap initialization: no heap in boot, uses static only.
unsafe fn init_heap_early() -> bool { true }

/// Safe idle loop: hlt forever, updates VGA for diagnostics.
unsafe fn safe_idle_loop() -> ! {
    let vga = 0xb8000 as *mut u16;
    *vga.add(240) = 0x0F49; // 'I'
    *vga.add(241) = 0x0F44; // 'D'
    *vga.add(242) = 0x0F4C; // 'L'
    *vga.add(243) = 0x0F45; // 'E'
    *vga.add(244) = 0x0F20; // ' '
    *vga.add(245) = 0x0F4C; // 'L'
    *vga.add(246) = 0x0F4F; // 'O'
    *vga.add(247) = 0x0F4F; // 'O'
    *vga.add(248) = 0x0F50; // 'P'
    loop {
        core::arch::asm!("hlt");
        static mut COUNTER: u16 = 0;
        COUNTER = COUNTER.wrapping_add(1);
        *vga.add(249) = 0x0F00 | ((COUNTER % 10) as u16 + b'0' as u16);
    }
}
