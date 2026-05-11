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

#![no_std]
#![no_main]

extern crate alloc;
extern crate nonos_kernel;

use core::arch::naked_asm;
use core::sync::atomic::{AtomicU64, Ordering};

mod manifest_embed {
    include!(concat!(env!("OUT_DIR"), "/manifest_data.rs"));
}
pub use manifest_embed::*;

use nonos_kernel::boot::handoff::init_handoff;
use nonos_kernel::boot::main::init_core_systems;
use nonos_kernel::entry::{fallback, security};
use nonos_kernel::sys::serial;

static HANDOFF_PTR: AtomicU64 = AtomicU64::new(0);

#[unsafe(naked)]
#[no_mangle]
#[link_section = ".text._start"]
pub extern "C" fn _start() -> ! {
    naked_asm!(
        "cli", "cld", "push rdi",
        "mov dx, 0x3F8", "mov al, 'A'", "out dx, al",
        "finit",
        "mov dx, 0x3F8", "mov al, 'B'", "out dx, al",
        "mov rax, cr0", "and eax, 0xFFFFFFFB", "or eax, 0x00000022", "mov cr0, rax",
        "mov dx, 0x3F8", "mov al, 'C'", "out dx, al",
        "mov rax, cr4", "or eax, 0x00000600", "mov cr4, rax",
        "mov dx, 0x3F8", "mov al, 'D'", "out dx, al",
        "pop rdi",
        "mov dx, 0x3F8", "mov al, 'E'", "out dx, al", "mov al, 0x0A", "out dx, al",
        "call {rust_entry}", "2:", "cli", "hlt", "jmp 2b",
        rust_entry = sym kernel_entry,
    )
}

#[no_mangle]
extern "C" fn kernel_entry(handoff_ptr: u64) -> ! {
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8", "mov al, 'R'", "out dx, al",
            "mov al, 0x0A", "out dx, al",
            out("dx") _, out("al") _,
        );
    }
    HANDOFF_PTR.store(handoff_ptr, Ordering::SeqCst);
    if handoff_ptr == 0 {
        serial::println(b"[NONOS] CRITICAL: No handoff!");
        fallback::vga_fallback();
    }
    let handoff = match unsafe { init_handoff(handoff_ptr) } {
        Ok(h) => {
            serial::println(b"[NONOS] Handoff OK");
            h
        }
        Err(err) => {
            serial::println(b"[NONOS] Handoff FAIL");
            serial::print(b"[NONOS] Handoff ERR: ");
            serial::print_str(err.as_str());
            serial::println(b"");
            fallback::vga_fallback();
        }
    };
    init_core_systems();
    security::log_security_status(handoff);
    boot_microkernel(handoff)
}

fn boot_microkernel(handoff: &nonos_kernel::boot::handoff::BootHandoffV1) -> ! {
    if handoff.fb.ptr == 0 {
        serial::println(b"[NONOS] No framebuffer");
        fallback::vga_fallback();
    }
    serial::println(b"[NONOS] Microkernel boot");
    let kernel_handoff = nonos_kernel::boot::handoff::KernelHandoff::from_x86_64(handoff);
    nonos_kernel::kernel_core::microkernel_init(&kernel_handoff);

    // Tests disabled for production boot

    nonos_kernel::kernel_core::microkernel_main()
}
