//! x86_64 Boot Entry Point

use core::arch::asm;

/// The actual entry point from bootloader (DISABLED)
/*
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _arch_start() -> ! {
    // Set up stack
    asm!(
        "mov rsp, {}",
        "mov rbp, rsp",
        "call {}",
        in(reg) &__boot_stack_top as *const u8 as u64,
        sym kernel_main,
        options(noreturn)
    );
}
*/

/*
#[no_mangle]
unsafe extern "C" fn kernel_main() -> ! {
    // Initialize subsystems in order
    crate::arch::boot::init_early();
    
    // Initialize memory
    init_memory();
    
    // Initialize CPU structures
    init_cpu();
    
    // Initialize interrupts
    init_interrupts();
    
    // Start scheduler
    crate::sched::enter();
}
*/

unsafe fn init_memory() {
    // Initialize physical memory allocator
    use crate::memory::phys;
    
    // Simple memory regions for initial testing
    let regions = &[
        crate::memory::layout::Region {
            start: 0x100000,
            end: 0x100000 + 0x1000000,
            kind: crate::memory::layout::RegionKind::Usable,
        },
    ];
    
    // Provide bitmap backing
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
    
    // Initialize virtual memory
    use x86_64::registers::control::Cr3;
    let (frame, _) = Cr3::read();
    crate::memory::virt::init(frame.start_address().as_u64()).ok();
    
    // Initialize kernel heap with default policy
    crate::memory::alloc::init(crate::memory::alloc::HeapPolicy::default());
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
