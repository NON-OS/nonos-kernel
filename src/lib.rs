// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

// Kernel root crate. Freestanding x86_64, no std.
//
// Core:
//   arch        x86_64: GDT, IDT, APIC, TSC, paging, syscall entry
//   boot        multiboot2 handoff, early VGA, memory map parsing
//   interrupts  exception handlers, IRQ routing
//   smp         multi-core init, IPI, per-CPU data
//   sys         low-level: serial, clock, timer, GDT/IDT wrappers
//   syscall     syscall table, handlers, extended syscalls
//
// Memory:
//   memory      frame allocator, virtual memory, heap, DMA, KASLR
//   mem         unified memory API
//
// Storage & FS:
//   storage     block device layer, partition tables
//   fs          VFS, ramfs, cryptofs
//   elf         ELF loader, dynamic linking, relocations
//
// Drivers:
//   drivers     PCI, NVMe, AHCI, e1000, RTL8139, xHCI, I2C, VGA, console
//   bus         bus abstraction layer
//   input       PS/2, USB HID, I2C HID touchpad with gestures
//
// Network:
//   network     TCP/IP stack, DNS, DHCP, HTTP client, onion routing, firewall
//
// Graphics & UI:
//   graphics    framebuffer, window manager, desktop, themes
//   ui          CLI, TUI, GUI bridge, clipboard
//   shell       command interpreter, vi-style editor
//
// Crypto & ZK:
//   crypto      AES-GCM, ChaCha20, SHA2/3, BLAKE3, Ed25519, secp256k1, Kyber, SPHINCS+
//   zk_engine   Groth16, PLONK verifiers, circuit attestation
//   vault       encrypted key storage, TPM sealing
//   security    secure boot, capabilities, memory sanitization
//
// Process & Scheduling:
//   process     PCB, userspace, clone/fork
//   sched       cooperative scheduler, async executor
//   runtime     capsule runtime, supervisor
//   capabilities process permissions
//
// IPC & Services:
//   ipc         message passing, pipes, shared memory
//   daemon      background services
//   monitor     system monitor
//
// Apps:
//   apps        ecosystem: wallet, browser, staking, LP, privacy tools
//   npkg        package manager
//
// Misc:
//   log         kernel logging macros
//   modules     loadable module support
//   test        test framework
//   kernel_selftest  crypto KATs, memory checks
//
// Boot flow: GRUB -> kernel_main -> VGA/panic init -> drivers -> selftest -> scheduler

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
