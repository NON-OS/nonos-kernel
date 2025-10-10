// Virtual Memory Management — thin over memory::virt

use x86_64::{
    VirtAddr, PhysAddr,
    structures::paging::{PageTableFlags, Size4KiB, Page, PhysFrame},
};

use spin::Mutex;

use crate::memory::{virt, virt::VmFlags};
use crate::memory::frame_alloc::{allocate_frame, deallocate_frame};

pub struct VirtualMemoryManager;

impl VirtualMemoryManager {
    pub unsafe fn new(_physical_offset: VirtAddr) -> Self {
        VirtualMemoryManager
    }

    pub fn map_page(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let vmf = pte_to_vmflags(flags)?;
        virt::map4k_at(
            VirtAddr::new(page.start_address().as_u64()),
            PhysAddr::new(frame.start_address().as_u64()),
            vmf,
        ).map_err(|_| "map failed")
    }

    pub fn unmap_page(&mut self, page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, &'static str> {
        let va = VirtAddr::new(page.start_address().as_u64());
        let (pa, _fl, _sz) = virt::translate(va).map_err(|_| "not mapped")?;
        virt::unmap4k(va).map_err(|_| "unmap failed")?;
        Ok(PhysFrame::containing_address(pa))
    }

    pub fn translate_addr(&self, addr: VirtAddr) -> Option<PhysAddr> {
        virt::translate(addr).ok().map(|(pa, _f, _s)| pa)
    }

    pub fn map_range(
        &mut self,
        start_page: Page<Size4KiB>,
        start_frame: PhysFrame<Size4KiB>,
        page_count: usize,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let base_va = VirtAddr::new(start_page.start_address().as_u64());
        let base_pa = PhysAddr::new(start_frame.start_address().as_u64());
        let vmf = pte_to_vmflags(flags)?;
        virt::map_range_4k_at(base_va, base_pa, page_count * 4096, vmf).map_err(|_| "map range failed")
    }

    pub fn identity_map_range(
        &mut self,
        start_addr: PhysAddr,
        size: usize,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let vmf = pte_to_vmflags(flags)?;
        virt::map_range_4k_at(VirtAddr::new(start_addr.as_u64()), start_addr, size, vmf).map_err(|_| "map id failed")
    }

    pub fn higher_half_map_range(
        &mut self,
        phys_start: PhysAddr,
        virt_start: VirtAddr,
        size: usize,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let vmf = pte_to_vmflags(flags)?;
        virt::map_range_4k_at(virt_start, phys_start, size, vmf).map_err(|_| "map hh failed")
    }
}

static VMEM_MANAGER: Mutex<Option<VirtualMemoryManager>> = Mutex::new(None);

pub fn init_virtual_memory() -> Result<(), &'static str> {
    let mut manager = unsafe { VirtualMemoryManager::new(VirtAddr::new(0)) };

    // VGA text (identity)
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    manager.identity_map_range(PhysAddr::new(0xB8000), 4096, flags)?;

    // First 16 MiB identity (for early phys access if needed)
    manager.identity_map_range(PhysAddr::new(0), 16 * 1024 * 1024, flags)?;

    // Kernel heap mapping
    let heap_start = crate::memory::heap::HEAP_START as u64;
    let heap_size = crate::memory::heap::HEAP_SIZE;
    let heap_pages = (heap_size + 4095) / 4096;
    for i in 0..heap_pages {
        if let Some(frame_pa) = allocate_frame() {
            let page = Page::containing_address(VirtAddr::new(heap_start + (i * 4096) as u64));
            manager.map_page(page, PhysFrame::containing_address(frame_pa), flags)?;
        } else {
            return Err("heap frames exhausted");
        }
    }

    *VMEM_MANAGER.lock() = Some(manager);
    Ok(())
}

pub fn map_memory_range(
    virt_addr: VirtAddr,
    phys_addr: PhysAddr,
    size: usize,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let mut g = VMEM_MANAGER.lock();
    let vm = g.as_mut().ok_or("vm not initialized")?;
    vm.higher_half_map_range(phys_addr, virt_addr, size, flags)
}

pub fn unmap_memory_range(virt_addr: VirtAddr, size: usize) -> Result<(), &'static str> {
    let mut g = VMEM_MANAGER.lock();
    let vm = g.as_mut().ok_or("vm not initialized")?;
    let start_page = Page::containing_address(virt_addr);
    let page_count = (size + 4095) / 4096;
    for i in 0..page_count {
        let page = start_page + i as u64;
        match vm.unmap_page(page) {
            Ok(frame) => deallocate_frame(frame.start_address()),
            Err(_) => return Err("unmap page failed"),
        }
    }
    Ok(())
}

pub fn translate_virtual_address(virt_addr: VirtAddr) -> Option<PhysAddr> {
    virt::translate(virt_addr).ok().map(|(pa, _f, _s)| pa)
}

pub fn is_mapped(virt_addr: VirtAddr) -> bool {
    translate_virtual_address(virt_addr).is_some()
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
