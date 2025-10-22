//! NONOS Kernel core crate

#![no_std]
#![feature(alloc_error_handler)]
#![feature(asm_sym)]
#![feature(naked_functions)]
#![feature(abi_x86_interrupt)]
// #![deny(warnings)]
// #![deny(unused_must_use, unused_imports, unused_variables, unused_mut)]
// #![deny(unsafe_op_in_unsafe_fn)]
#![allow(warnings)]
#![allow(unused_must_use, unused_imports, unused_variables, unused_mut)]
#![allow(unsafe_op_in_unsafe_fn)]

#[macro_use]
extern crate alloc;

// Core kernel modules.
mod arch;
mod boot;
mod capabilities;
mod crypto;
mod drivers;
mod elf;
pub mod fs;
mod interrupts;
mod ipc;
mod kernel_selftest;
mod log;
mod memory;
mod modules;
mod monitor;
mod network;
pub mod nonos_time;
mod process;
mod runtime;
mod sched;
mod security;
pub mod storage;
mod syscall;
mod ui;
mod vault;
mod zk_engine;

// Time module re-export
pub use nonos_time as time;

// Filesystem re-export (from storage)
pub use fs as filesystem;
 
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::boot::init_vga_output();
    crate::boot::init_panic_handler();
    crate::boot::init_early();

    // Initialize drivers. 
    if let Err(err) = crate::drivers::init_all_drivers() {
        early_vga_error(format_args!("DRIVERS INIT FAILED: {:#?}", err));
        halt_loop();
    }

    // Announce kernel readiness if console present.
    crate::drivers::console::write_message("kernel online");

    // self-tests + reports
    let ok = crate::kernel_selftest::run();
    if !ok {
        crate::drivers::console::write_message("selftest degraded");
    }

    // Optional CLI
    #[cfg(feature = "cli")]
    {
        crate::ui::cli::spawn();
    }

    // Enter scheduler
    #[cfg(feature = "sched")]
    unsafe {
        crate::sched::enter();
    }

    // Scheduler absent or returns unexpectedly — halt safely.
    halt_loop();
}

/// Bounded, allocation-free formatting into VGA text buffer for early diagnostics.
///
/// Writes up to 256 bytes of the formatted args into VGA text memory (0xb8000).
fn early_vga_error(args: core::fmt::Arguments<'_>) {
    // Stack buffer to avoid allocations.
    let mut buf = [0u8; 256];
    use core::fmt::Write;
    struct SliceWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl<'a> core::fmt::Write for SliceWriter<'a> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let avail = self.buf.len().saturating_sub(self.pos);
            let to_copy = core::cmp::min(avail, bytes.len());
            if to_copy == 0 {
                return Err(core::fmt::Error);
            }
            self.buf[self.pos..self.pos + to_copy].copy_from_slice(&bytes[..to_copy]);
            self.pos += to_copy;
            Ok(())
        }
    }

    let mut writer = SliceWriter { buf: &mut buf, pos: 0 };
    let _ = writer.write_fmt(args);
    let len = writer.pos;

    unsafe {
        // VGA (physical address mapped into identity region).
        let vga_base = 0xb8000 as *mut u16;
        let attr: u16 = 0x4F00;
        for i in 0..len {
            let b = buf[i] as u16;
            core::ptr::write_volatile(vga_base.add(i), b | attr);
        }
    }
}

/// CPU halt loop.
#[inline(always)]
fn halt_loop() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}

// Logging macros defined in log module      
