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

use spin::Once;
use x86_64::structures::paging::PageTable;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::phys::AllocFlags;
use super::serial::serial_print;
use super::types::{BootInfo, EFI_CONVENTIONAL_MEMORY, MemoryDescriptor};

static USABLE_REGIONS: Once<heapless::Vec<crate::memory::layout::Region, 32>> = Once::new();
fn validate_memory_region(desc: &MemoryDescriptor) -> Result<(), &'static str> {
    const PAGE_SIZE: u64 = 4096;
    const MAX_PHYSICAL_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;
    if desc.page_count == 0 {
        return Err("Zero page count in memory region");
    }

    if desc.phys_start & (PAGE_SIZE - 1) != 0 {
        return Err("Memory region not page-aligned");
    }

    let end_addr = desc
        .phys_start
        .checked_add(desc.page_count.checked_mul(PAGE_SIZE).ok_or("Page count overflow")?)
        .ok_or("Address overflow in memory region")?;

    if desc.phys_start > MAX_PHYSICAL_ADDR || end_addr > MAX_PHYSICAL_ADDR {
        return Err("Memory region exceeds physical address space");
    }

    if desc.phys_start == 0 {
        return Err("Memory region starts at null page");
    }

    Ok(())
}

fn check_region_overlap(
    regions: &heapless::Vec<crate::memory::layout::Region, 32>,
    new_start: u64,
    new_end: u64,
) -> bool {
    for region in regions.iter() {
        let existing_start = region.start_addr();
        let existing_end = region.end_addr();
        if new_start < existing_end && new_end > existing_start {
            return true;
        }
    }
    false
}
/// # Safety {
/// Must be called exactly once during early boot with valid boot info.
/// The boot_info pointer must remain valid for the kernel lifetime.
/// }
pub unsafe fn init_memory(boot_info: &'static BootInfo) -> Result<(), &'static str> {
    if USABLE_REGIONS.is_completed() {
        return Err("Memory already initialized");
    }

    let mut regions = heapless::Vec::<crate::memory::layout::Region, 32>::new();
    let mut skipped_regions = 0u32;
    for desc in boot_info.memory_map {
        if desc.ty == EFI_CONVENTIONAL_MEMORY {
            if let Err(e) = validate_memory_region(desc) {
                serial_print(format_args!(
                    "[BOOT] Skipping invalid memory region at {:#x}: {}\n",
                    desc.phys_start, e
                ));
                skipped_regions += 1;
                continue;
            }

            let region_start = desc.phys_start;
            let region_end = desc.phys_start + desc.page_count * 4096;
            if check_region_overlap(&regions, region_start, region_end) {
                serial_print(format_args!(
                    "[BOOT] Skipping overlapping memory region at {:#x}-{:#x}\n",
                    region_start, region_end
                ));
                skipped_regions += 1;
                continue;
            }

            if regions.push(crate::memory::layout::Region {
                start: region_start,
                end: region_end,
                kind: crate::memory::layout::RegionKind::Usable,
            }).is_err() {
                serial_print(format_args!(
                    "[BOOT] Memory region table full, skipping region at {:#x}\n",
                    region_start
                ));
                break;
            }
        }
    }

    if skipped_regions > 0 {
        serial_print(format_args!(
            "[BOOT] Skipped {} invalid/overlapping memory regions\n",
            skipped_regions
        ));
    }

    if regions.is_empty() {
        return Err("No usable memory regions found");
    }

    serial_print(format_args!(
        "[BOOT] Found {} usable memory regions\n",
        regions.len()
    ));

    let first_region_start = regions[0].start_addr();
    let first_region_end = regions[0].end_addr();
    USABLE_REGIONS.call_once(|| regions);
    // # SAFETY: Physical memory addresses validated above
    unsafe {
        crate::memory::phys::init(
            PhysAddr::new(first_region_start),
            PhysAddr::new(first_region_end),
        )
        .map_err(|_| "Failed to initialize physical memory")?;
    }

    let phys_offset = VirtAddr::new(0xFFFF_8000_0000_0000);
    // # SAFETY: Reading CR3 to get page table address
    let l4_table = unsafe { get_level_4_table(phys_offset) };
    // # SAFETY: Page table address from CR3 is valid
    unsafe {
        crate::memory::virt::init(PhysAddr::new(l4_table as u64))
            .map_err(|_| "Virtual memory init failed")?;
    }

    const HEAP_SIZE: usize = 8 * 1024 * 1024;
    let heap_start = VirtAddr::new(0xFFFF_8800_0000_0000);
    for i in 0..(HEAP_SIZE / 4096) {
        let page = heap_start + (i * 4096) as u64;
        let frame = crate::memory::phys::alloc(AllocFlags::empty())
            .ok_or("Failed to allocate heap frame")?;
        // # SAFETY: Frame allocated from validated physical memory
        unsafe {
            crate::memory::virt::map_page_4k(page, PhysAddr::new(frame.0), true, false, false)
                .map_err(|_| "Failed to map heap page")?;
        }
    }
    // # SAFETY: Heap memory mapped above
    unsafe {
        crate::memory::heap::init().map_err(|_| "Failed to initialize heap")?;
    }

    Ok(())
}
// # SAFETY: Reading CR3 register to get L4 page table address
unsafe fn get_level_4_table(phys_offset: VirtAddr) -> *mut PageTable {
    use x86_64::registers::control::Cr3;
    let (l4_frame, _) = Cr3::read();
    let phys = l4_frame.start_address();
    let virt = phys_offset + phys.as_u64();
    virt.as_mut_ptr()
}
