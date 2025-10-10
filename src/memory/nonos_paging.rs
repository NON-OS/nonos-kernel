// NØNOS Paging — delegates to memory::virt

use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{PageTableFlags, Page, Size4KiB, PhysFrame},
};

use crate::memory::{virt, virt::VmFlags};
use crate::memory::frame_alloc;

/// Virtual offset used for kernel-to-physical mapping (higher-half)
const PHYS_MEM_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Initialize basic paging for the kernel: map the first 16 MiB into the higher-half window.
pub fn init() {
    let flags = VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL;
    // Map [0, 16MiB) at higher-half + phys
    let _ = virt::map_range_4k_at(
        VirtAddr::new(PHYS_MEM_OFFSET),
        PhysAddr::new(0),
        16 * 1024 * 1024,
        flags,
    );
}

/// Map a single page to a newly-allocated physical frame with the requested flags.
pub unsafe fn map_page(page: Page<Size4KiB>, flags: PageTableFlags) -> Result<(), &'static str> {
    let pa = frame_alloc::alloc_frame()
        .map(|f: PhysFrame<Size4KiB>| f.start_address())
        .ok_or("no frames")?;
    let v = VirtAddr::new(page.start_address().as_u64());
    let vmf = pte_to_vmflags(flags)?;
    virt::map4k_at(v, pa, vmf).map_err(|_| "map failed")
}

#[inline]
fn pte_to_vmflags(f: PageTableFlags) -> Result<VmFlags, &'static str> {
    let mut vm = VmFlags::GLOBAL;
    if f.contains(PageTableFlags::WRITABLE) { vm |= VmFlags::RW | VmFlags::NX; }
    if f.contains(PageTableFlags::USER_ACCESSIBLE) { vm |= VmFlags::USER; }
    if f.contains(PageTableFlags::NO_EXECUTE) { vm |= VmFlags::NX; }
    if f.contains(PageTableFlags::PWT) { vm |= VmFlags::PWT; }
    if f.contains(PageTableFlags::PCD) { vm |= VmFlags::PCD; }
    Ok(vm)
}
