// kernel/src/boot.rs
//! NØNOS Complete Boot Sequence

use core::panic::PanicInfo;
use x86_64::{PhysAddr, VirtAddr};

// The very first code that runs - boot entry point (DISABLED)
/*
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    // Set up initial stack (we'll use a static buffer)
    static mut BOOT_STACK: [u8; 0x4000] = [0; 0x4000];
    let stack_top = BOOT_STACK.as_ptr().add(BOOT_STACK.len()) as *const u8;

    core::arch::asm!(
        "mov rsp, {}",
        "mov rbp, rsp",
        "call {}",
        in(reg) stack_top,
        sym kernel_main,
        options(noreturn)
    );
}
*/

/*
#[no_mangle]
unsafe extern "C" fn kernel_main() -> ! {
    // Stage 1: Early initialization
    init_early();

    // Stage 2: Memory
    init_memory();

    // Stage 3: CPU structures
    init_cpu();

    // Stage 4: Interrupts
    init_interrupts();

    // Stage 5: Subsystems
    init_subsystems();

    // Stage 6: Enter scheduler
    loop {
        x86_64::instructions::hlt();
    }
}
*/

unsafe fn init_early() {
    // Initialize serial port for debugging
    use crate::arch::x86_64::serial;
    serial::init();

    // Initialize VGA
    use crate::arch::x86_64::vga;
    vga::clear();
    vga::print("[BOOT] NØNOS ZeroState Kernel\n");
}

unsafe fn init_memory() {
    use crate::memory::{heap, layout, phys, virt};

    // Simple memory map for testing
    let regions = &[layout::Region {
        start: 0x100000,
        end: 0x100000 + 0x1000000,
        kind: layout::RegionKind::Usable,
    }];

    // Initialize physical allocator
    static mut BITMAP: [core::sync::atomic::AtomicU64; 1024] = {
        const INIT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        [INIT; 1024]
    };

    phys::init_from_regions(
        regions,
        0,
        phys::ScrubPolicy::OnFree,
        |words| &mut BITMAP[..words],
        None,
    );

    // Get current page table
    use x86_64::registers::control::Cr3;
    let (frame, _) = Cr3::read();

    // Initialize virtual memory
    let _ = virt::init(frame.start_address().as_u64());

    // Initialize heap
    heap::init();
}

unsafe fn init_cpu() {
    use crate::arch::x86_64::{gdt, idt};

    // Simple IST allocator
    struct SimpleAllocator;
    impl gdt::IstAllocator for SimpleAllocator {
        unsafe fn alloc_with_guard(&self, len: usize) -> (VirtAddr, VirtAddr) {
            static mut BUFFER: [u8; 0x8000] = [0; 0x8000];
            static mut OFFSET: usize = 0;

            let start = VirtAddr::new(&BUFFER[OFFSET] as *const u8 as u64);
            OFFSET += len;
            let end = VirtAddr::new(&BUFFER[OFFSET] as *const u8 as u64);
            (start, end)
        }

        unsafe fn free_with_guard(&self, _: VirtAddr, _: usize) {}
    }

    let alloc = SimpleAllocator;
    gdt::init_bsp(0, &alloc);
    idt::init();
}

unsafe fn init_interrupts() {
    use crate::arch::x86_64::interrupt::apic;
    use crate::arch::x86_64::time::timer;

    apic::init();
    timer::init();

    x86_64::instructions::interrupts::enable();
}

unsafe fn init_subsystems() {
    use crate::{crypto, ipc, modules, sched, ui};

    crypto::init_crypto();
    sched::init();
    ipc::init_ipc();
    modules::mod_loader::init_module_loader();
    ui::cli::spawn();
}

// Panic handler removed to avoid duplication - using the one from boot/mod.rs
