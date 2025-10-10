#![no_std]
#![deny(warnings)]
#![deny(unused_must_use, unused_imports, unused_variables, unused_mut)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod kernel_selftest;

pub fn kernel_main() {
    crate::boot::init_vga_output();
    crate::boot::init_panic_handler();
    crate::boot::init_early();

    if let Err(_e) = crate::drivers::init_all_drivers() {
        unsafe {
            let vga = 0xb8000 as *mut u8;
            let msg = b"DRIVERS INIT FAILED";
            for (i, &b) in msg.iter().enumerate() {
                let off = i * 2;
                core::ptr::write_volatile(vga.add(off), b);
                core::ptr::write_volatile(vga.add(off + 1), 0x4F);
            }
        }
        loop {
            unsafe { core::arch::asm!("hlt"); }
        }
    }

    crate::drivers::console::write_message(
        "kernel online",
        crate::drivers::console::LogLevel::Info,
        "kernel",
    );

    let ok = crate::kernel_selftest::run();
    if !ok {
        crate::drivers::console::write_message(
            "selftest degraded",
            crate::drivers::console::LogLevel::Warning,
            "kernel",
        );
    }

    #[cfg(feature = "cli")]
    {
        crate::ui::cli::spawn();
    }

    #[cfg(feature = "sched")]
    unsafe {
        crate::sched::enter();
    }

    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
