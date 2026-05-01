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

use core::arch::asm;

use super::info::BootInfo;

#[naked]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        "mrs x0, mpidr_el1",
        "and x0, x0, #0xFF",
        "cbnz x0, .Lsecondary",

        "adrp x0, __stack_top",
        "add x0, x0, :lo12:__stack_top",
        "mov sp, x0",

        "bl _clear_bss",
        "bl kernel_entry",

        ".Lsecondary:",
        "wfe",
        "b .Lsecondary",

        options(noreturn)
    )
}

#[no_mangle]
pub unsafe extern "C" fn _clear_bss() {
    extern "C" {
        static mut __bss_start: u8;
        static mut __bss_end: u8;
    }

    let start = &mut __bss_start as *mut u8;
    let end = &mut __bss_end as *mut u8;
    let len = end as usize - start as usize;

    core::ptr::write_bytes(start, 0, len);
}

#[no_mangle]
pub extern "C" fn kernel_entry(dtb_ptr: u64) -> ! {
    let boot_info = parse_dtb(dtb_ptr);

    super::init(&boot_info);

    crate::kernel_main();
}

fn parse_dtb(dtb_ptr: u64) -> BootInfo {
    let mut info = BootInfo::default();

    if dtb_ptr != 0 && is_valid_dtb(dtb_ptr) {
        parse_dtb_memory(dtb_ptr, &mut info);
        parse_dtb_devices(dtb_ptr, &mut info);
    } else {
        info.ram_base = 0x4000_0000;
        info.ram_size = 0x1_0000_0000;
        info.uart_base = 0x0900_0000;
        info.gic_dist_base = 0x0800_0000;
        info.gic_redist_base = 0x080A_0000;
    }

    info
}

fn is_valid_dtb(ptr: u64) -> bool {
    const FDT_MAGIC: u32 = 0xD00D_FEED;

    let magic = unsafe { *(ptr as *const u32) };
    u32::from_be(magic) == FDT_MAGIC
}

fn parse_dtb_memory(dtb_ptr: u64, info: &mut BootInfo) {
    let _ = (dtb_ptr, info);
}

fn parse_dtb_devices(dtb_ptr: u64, info: &mut BootInfo) {
    let _ = (dtb_ptr, info);
}
