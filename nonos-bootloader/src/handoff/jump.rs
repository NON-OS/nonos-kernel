// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

/*
 * Issue #8 fix: ExitBootServices hang on real hardware
 *
 * Users on i5-11400H + GTX 3050, HP EliteDesk, Acer boards saw freezes.
 * Root cause: memory map thrown away after ExitBootServices. Kernel got
 * ptr=0 entry_count=0. Real machines have ACPI regions, PCI MMIO holes,
 * firmware reserved areas everywhere. Kernel heap init stomped on those.
 *
 * QEMU works because memory is one big chunk. Real hardware is fragmented.
 *
 * Fix: allocate buffer before ExitBootServices, copy mmap after, pass to
 * kernel via BootHandoffV1.mmap.
 */

use core::mem::size_of;
use uefi::table::boot::MemoryMap as UefiMemoryMap;

use super::prepare::MAX_MMAP_ENTRIES;
use super::types::MemoryMap;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryMapEntry {
    pub memory_type: u32,
    pub _pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

pub fn copy_memory_map(
    mmap_addr: u64,
    final_mmap: &UefiMemoryMap<'_>,
) -> (u64, u32, u32) {
    let mmap_buffer = mmap_addr as *mut MemoryMapEntry;
    let mut entry_count: u32 = 0;

    unsafe {
        for desc in final_mmap.entries() {
            if (entry_count as usize) >= MAX_MMAP_ENTRIES {
                break;
            }
            let entry = mmap_buffer.add(entry_count as usize);
            (*entry).memory_type = desc.ty.0;
            (*entry)._pad = 0;
            (*entry).physical_start = desc.phys_start;
            (*entry).virtual_start = desc.virt_start;
            (*entry).page_count = desc.page_count;
            (*entry).attribute = desc.att.bits();
            entry_count += 1;
        }
    }

    (mmap_addr, size_of::<MemoryMapEntry>() as u32, entry_count)
}

pub fn finalize_mmap(
    bh_ptr: *mut super::types::BootHandoffV1,
    mmap_addr: u64,
    entry_size: u32,
    entry_count: u32,
) {
    unsafe {
        (*bh_ptr).mmap = MemoryMap {
            ptr: mmap_addr,
            entry_size,
            entry_count,
            desc_version: 1,
        };
    }
}

/*
 * Settle delay before ExitBootServices
 *
 * Some firmware has race conditions in exit handlers. HP EliteDesk,
 * Acer boards, ASUS TUF Gaming, and MSI laptops hang without this.
 * Extended to ~50ms for wider hardware compatibility.
 * Issue #8: Users on i5-11400H, Ryzen 5 7535HS, Ryzen 7 5800X3D reported hangs.
 */
#[inline]
pub fn settle_delay() {
    for _ in 0..5_000_000 {
        core::hint::spin_loop();
    }
}

/*
 * Issue #8 hardened kernel jump
 *
 * On real hardware the CPU state after ExitBootServices can be unpredictable.
 * We explicitly:
 * - Disable interrupts (cli)
 * - Clear direction flag (cld)
 * - Flush caches (wbinvd) - helps on some ASUS/MSI boards
 * - Clear segment registers to known state
 * - Align stack to 16 bytes (ABI requirement)
 * - Zero frame pointer
 *
 * Tested on: HP EliteDesk, Lenovo X1, ASUS TUF Gaming, Acer Nitro
 */
#[inline(never)]
pub unsafe fn jump_to_kernel(
    entry_addr: u64,
    stack_top: u64,
    boothandoff_ptr: u64,
) -> ! {
    let stack_aligned = stack_top & !0xF;
    core::arch::asm!(
        "cli",
        "cld",
        "wbinvd",
        "mov rax, {entry}",
        "mov rcx, {stack}",
        "mov rdi, {handoff}",
        "xor rdx, rdx",
        "mov ds, dx",
        "mov es, dx",
        "mov fs, dx",
        "mov gs, dx",
        "mov rsp, rcx",
        "xor rbp, rbp",
        "xor rsi, rsi",
        "xor r8, r8",
        "xor r9, r9",
        "xor r10, r10",
        "xor r11, r11",
        "jmp rax",
        entry = in(reg) entry_addr,
        stack = in(reg) stack_aligned,
        handoff = in(reg) boothandoff_ptr,
        options(noreturn)
    );
}
