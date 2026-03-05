#![no_std]
#![feature(alloc_error_handler)]
#![feature(abi_x86_interrupt)]
#![allow(unsafe_op_in_unsafe_fn)]

#[macro_use]
extern crate alloc;

use core::alloc::Layout;

#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    // SAFETY: Direct port I/O for emergency output when heap is exhausted
    unsafe {
        fn serial_byte(b: u8) {
            unsafe {
                core::arch::asm!(
                    "out dx, al",
                    in("dx") 0x3F8u16,
                    in("al") b,
                    options(nomem, nostack)
                );
            }
        }

        fn serial_str(s: &[u8]) {
            for &b in s {
                serial_byte(b);
            }
        }

        fn serial_num(mut n: usize) {
            if n == 0 {
                serial_byte(b'0');
                return;
            }
            let mut buf = [0u8; 20];
            let mut i = 0;
            while n > 0 {
                buf[i] = b'0' + (n % 10) as u8;
                n /= 10;
                i += 1;
            }
            while i > 0 {
                i -= 1;
                serial_byte(buf[i]);
            }
        }

        serial_str(b"\r\n[OOM] ALLOCATION FAILED\r\n");
        serial_str(b"[OOM] Requested size: ");
        serial_num(layout.size());
        serial_str(b" bytes, align: ");
        serial_num(layout.align());
        serial_str(b"\r\n");
        serial_str(b"[OOM] System halted\r\n");

        // SAFETY: VGA text buffer at 0xb8000 is identity-mapped
        let vga_base = 0xb8000 as *mut u16;
        let msg = b"OOM: Memory allocation failed - system halted";
        let attr: u16 = 0x4F00;
        for (i, &ch) in msg.iter().enumerate() {
            core::ptr::write_volatile(vga_base.add(i), (ch as u16) | attr);
        }
    }

    loop {
        // SAFETY: HLT stops CPU until interrupt
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}

pub mod apps;
pub mod arch;
pub mod boot;
pub mod bus;
pub mod capabilities;
pub mod crypto;
pub mod daemon;
pub mod drivers;
pub mod elf;
pub mod fs;
pub mod graphics;
pub mod input;
pub mod interrupts;
pub mod ipc;
pub mod kernel_selftest;
pub mod log;
pub mod mem;
pub mod memory;
pub mod modules;
pub mod monitor;
pub mod network;
pub mod npkg;
pub mod process;
pub mod runtime;
pub mod sched;
pub mod security;
pub mod shell;
pub mod smp;
pub mod storage;
pub mod sys;
pub mod syscall;
pub mod test;
pub mod ui;
pub mod vault;
pub mod zk_engine;

pub use arch::x86_64::time as time;
pub use fs as filesystem;

pub static mut NEEDS_REDRAW: bool = false;

#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    crate::boot::init_vga_output();
    crate::boot::init_panic_handler();
    crate::boot::init_early();

    if let Err(err) = crate::drivers::init_all_drivers() {
        early_vga_error(format_args!("DRIVERS INIT FAILED: {:#?}", err));
        halt_loop();
    }

    crate::drivers::console::write_message("kernel online");

    let ok = crate::kernel_selftest::run();
    if !ok {
        crate::drivers::console::write_message("selftest degraded");
    }

    #[cfg(feature = "cli")]
    {
        crate::ui::cli::spawn();
    }

    #[cfg(feature = "sched")]
    {
        crate::sched::enter();
    }

    #[cfg(not(feature = "sched"))]
    halt_loop();
}

fn early_vga_error(args: core::fmt::Arguments<'_>) {
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

    // SAFETY: VGA text buffer at 0xb8000 is identity-mapped during early boot
    unsafe {
        let vga_base = 0xb8000 as *mut u16;
        let attr: u16 = 0x4F00;
        for i in 0..len {
            let b = buf[i] as u16;
            core::ptr::write_volatile(vga_base.add(i), b | attr);
        }
    }
}

#[inline(always)]
fn halt_loop() -> ! {
    loop {
        // SAFETY: HLT is always safe
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
    }
}
