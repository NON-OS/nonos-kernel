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
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        ".option push",
        ".option norelax",
        "la gp, __global_pointer$",
        ".option pop",
        "csrr t0, mhartid",
        "bnez t0, .Lsecondary_hart",
        "la sp, __stack_top",
        "la t0, __bss_start",
        "la t1, __bss_end",
        ".Lclear_bss:",
        "bgeu t0, t1, .Ldone_bss",
        "sd zero, 0(t0)",
        "addi t0, t0, 8",
        "j .Lclear_bss",
        ".Ldone_bss:",
        "mv a0, a1",
        "call kernel_entry",
        ".Lsecondary_hart:",
        "wfi",
        "j .Lsecondary_hart",
        options(noreturn)
    )
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
        info.ram_base = 0x8000_0000;
        info.ram_size = 0x1_0000_0000;
        info.uart_base = 0x1000_0000;
        info.plic_base = 0x0C00_0000;
        info.clint_base = 0x0200_0000;
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

pub fn hart_id() -> usize {
    let id: usize;
    unsafe {
        asm!("csrr {}, mhartid", out(reg) id, options(nostack));
    }
    id
}
