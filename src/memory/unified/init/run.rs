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

use core::sync::atomic::Ordering;

use super::clear_low_half::clear_low_half;
use super::count_pml4_entries::count_pml4_entries;
use super::print_dec::print_dec_usize;
use super::print_hex::print_hex_u64;
use super::state::VM_UNIFIED_INITIALIZED;
use crate::memory::frame_alloc;
use crate::memory::paging::manager::api as paging_api;

const KERNEL_HALF_START: usize = 256;
const KERNEL_HALF_END: usize = 512;

// Bring the unified VM layer up before any address-space-creating
// caller runs. Each step is a real precondition for
// `paging::manager::create_address_space`; if any fails the kernel
// fails loudly with a deterministic reason instead of letting a
// process-creation site surface a swallowed error later.
pub fn init_unified_vm() -> Result<(), &'static str> {
    if VM_UNIFIED_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    // Step 1: explicit paging-manager init. Reads CR3, registers
    // the kernel address space.
    if !paging_api::is_initialized() {
        paging_api::init().map_err(|_| "init_unified_vm: paging manager init failed")?;
    }

    // Step 2: confirm CR3 is recorded.
    let active = paging_api::active_page_table()
        .ok_or("init_unified_vm: no active page table after manager init")?;

    // Step 3: confirm the kernel address space was registered.
    if paging_api::address_spaces_count() == 0 {
        return Err("init_unified_vm: kernel address space not registered");
    }

    // Step 4: the kernel half of the active PML4 must already
    // contain mappings the bootloader installed (directmap, kernel
    // text, kernel heap). `create_address_space` clones entries
    // 256..511 from the active table; if every entry is zero, the
    // clone path returns `NoActivePageTable`. That mode is the
    // regression we are guarding against.
    let kernel_half_populated =
        unsafe { count_pml4_entries(active.as_u64(), KERNEL_HALF_START..KERNEL_HALF_END) };
    if kernel_half_populated == 0 {
        crate::sys::serial::print(b"[VM-INIT] kernel half empty; CR3=");
        print_hex_u64(active.as_u64());
        crate::sys::serial::println(b"");
        return Err(
            "init_unified_vm: bootloader CR3 has no kernel-half PML4 entries (256..511)",
        );
    }
    crate::sys::serial::print(b"[VM-INIT] kernel half populated entries: ");
    print_dec_usize(kernel_half_populated);
    crate::sys::serial::println(b"");

    // Step 5: prove the frame allocator can hand out a page.
    let probe = frame_alloc::allocate_frame()
        .ok_or("init_unified_vm: frame_alloc::allocate_frame returned None")?;
    let _ = frame_alloc::deallocate_frame(probe);

    // Step 6: drop the bootloader's low-half identity. Two
    // kernel-half entries means directmap (PML4[256]) plus kernel
    // text (PML4[511]) are both there; from here on the kernel
    // runs entirely from the upper half. One entry is the legacy
    // low-half ET_EXEC layout, where PML4[0] is still the kernel's
    // own text — leave it.
    if kernel_half_populated >= 2 {
        clear_low_half()?;
        crate::sys::serial::println(b"[VM-INIT] low half cleared");
    }

    Ok(())
}
