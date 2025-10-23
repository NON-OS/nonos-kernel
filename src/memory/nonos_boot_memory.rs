//! Boot Memory Management

use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr, structures::paging::PageTableFlags};
use crate::memory::layout::*;
use crate::memory::virt::{self, VmFlags};

/// Boot memory information from bootloader
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BootMemoryInfo {
    pub magic: u64,
    pub abi_version: u16,
    pub hdr_size: u16,
    pub boot_flags: u32,
    pub capsule_base: u64,
    pub capsule_size: u64,
    pub capsule_hash: [u8; 32],
    pub memory_start: u64,
    pub memory_size: u64,
    pub entropy: [u8; 32],
    pub rtc_utc: [u8; 8],
    pub reserved: [u8; 8],
}

/// Memory region types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMemoryType {
    Available,
    Reserved,
    Kernel,
    Bootloader,
    Firmware,
    HardwareReserved,
    Defective,
}

/// Memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct BootMemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub region_type: BootMemoryType,
    pub attributes: u32,
}

impl BootMemoryRegion {
    #[inline] pub fn size(&self) -> u64 { self.end.as_u64() - self.start.as_u64() }
    #[inline] pub fn is_available(&self) -> bool { matches!(self.region_type, BootMemoryType::Available) }
    #[inline] pub fn contains(&self, addr: PhysAddr) -> bool { addr >= self.start && addr < self.end }
}

/// Boot memory manager
pub struct BootMemoryManager {
    regions: Vec<BootMemoryRegion>,
    kernel_base: VirtAddr,
    kernel_size: u64,
    available_memory: u64,
    reserved_memory: u64,
    identity_mapped: bool,
}

impl BootMemoryManager {
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            kernel_base: VirtAddr::new(KERNEL_BASE),
            kernel_size: 0,
            available_memory: 0,
            reserved_memory: 0,
            identity_mapped: false,
        }
    }

    pub fn initialize_from_handoff(&mut self, handoff_addr: u64) -> Result<(), &'static str> {
        if handoff_addr == 0 {
            return self.initialize_default_layout();
        }

        let handoff = unsafe {
            let p = handoff_addr as *const BootMemoryInfo;
            if p.is_null() { return self.initialize_default_layout(); }
            p.read()
        };

        if handoff.magic != 0x3042_4F53_4F4E_4F4Eu64 || handoff.abi_version != 1 {
            crate::log_warn!("[boot_memory] invalid handoff; using defaults");
            return self.initialize_default_layout();
        }

        let memory_start = handoff.memory_start;
        let memory_size = handoff.memory_size;
        crate::log::logger::log_info!(
            "[boot_memory] handoff: mem_start=0x{:x} size=0x{:x}",
            memory_start, memory_size
        );

        self.create_regions_from_handoff(&handoff)?;
        self.setup_initial_mapping()?;
        Ok(())
    }

    fn create_regions_from_handoff(&mut self, handoff: &BootMemoryInfo) -> Result<(), &'static str> {
        self.regions.clear();

        // Low memory [0, 1MiB) reserved
        self.add_region(PhysAddr::new(0), PhysAddr::new(0x10_0000), BootMemoryType::Reserved, 0);

        // Kernel region (estimate from linker bounds)
        let kernel_start = PhysAddr::new(0x10_0000);
        let kernel_end = PhysAddr::new(kernel_start.as_u64() + self.estimate_kernel_size());
        self.add_region(kernel_start, kernel_end, BootMemoryType::Kernel, 0);

        // Bootloader capsule if present
        if handoff.capsule_size > 0 {
            let c0 = PhysAddr::new(handoff.capsule_base);
            let c1 = PhysAddr::new(handoff.capsule_base + handoff.capsule_size);
            self.add_region(c0, c1, BootMemoryType::Bootloader, 0);
        }

        // Main memory
        if handoff.memory_size > 0 {
            let mem_lo = kernel_end.as_u64().max(handoff.memory_start);
            let mem_hi = handoff.memory_start + handoff.memory_size;
            if mem_hi > mem_lo {
                let lo = PhysAddr::new(align_up(mem_lo, PAGE_SIZE as u64));
                let hi = PhysAddr::new(align_down(mem_hi, PAGE_SIZE as u64));
                if hi > lo {
                    self.add_region(lo, hi, BootMemoryType::Available, 0);
                    self.available_memory = hi.as_u64() - lo.as_u64();
                }
            }
        }

        self.add_high_memory_regions()?;
        self.regions.sort_by_key(|r| r.start.as_u64());

        crate::log::logger::log_info!(
            "[boot_memory] regions={}, available={} KiB",
            self.regions.len(),
            self.available_memory / 1024
        );
        Ok(())
    }

    fn initialize_default_layout(&mut self) -> Result<(), &'static str> {
        crate::log::logger::log_info!("[boot_memory] default layout");

        self.regions.clear();
        // Available low RAM [0, 0xA0000)
        self.add_region(PhysAddr::new(0x0), PhysAddr::new(0xA0000), BootMemoryType::Available, 0);
        // Reserved [0xA0000, 0x100000)
        self.add_region(PhysAddr::new(0xA0000), PhysAddr::new(0x100000), BootMemoryType::Reserved, 0);
        // Kernel [1MiB, 16MiB)
        self.add_region(PhysAddr::new(0x100000), PhysAddr::new(0x1000000), BootMemoryType::Kernel, 0);
        // Available [16MiB, 128MiB)
        self.add_region(PhysAddr::new(0x1000000), PhysAddr::new(0x8000000), BootMemoryType::Available, 0);

        self.available_memory = 0x7000000;
        self.setup_initial_mapping()?;
        Ok(())
    }

    fn add_high_memory_regions(&mut self) -> Result<(), &'static str> {
        // PCI hole [3GiB, 4GiB)
        self.add_region(PhysAddr::new(0xC000_0000), PhysAddr::new(0x1_0000_0000), BootMemoryType::HardwareReserved, 0);
        // LAPIC
        self.add_region(PhysAddr::new(0xFEE0_0000), PhysAddr::new(0xFEE0_1000), BootMemoryType::HardwareReserved, 0);
        // IOAPIC
        self.add_region(PhysAddr::new(0xFEC0_0000), PhysAddr::new(0xFEC0_1000), BootMemoryType::HardwareReserved, 0);
        Ok(())
    }

    fn add_region(&mut self, start: PhysAddr, end: PhysAddr, region_type: BootMemoryType, attributes: u32) {
        if start >= end { return; }
        let r = BootMemoryRegion { start, end, region_type, attributes };
        if matches!(region_type, BootMemoryType::Reserved | BootMemoryType::HardwareReserved) {
            self.reserved_memory += r.size();
        }
        self.regions.push(r);
    }

    fn estimate_kernel_size(&self) -> u64 {
        unsafe {
            let s = &crate::memory::layout::__kernel_start as *const _ as u64;
            let e = &crate::memory::layout::__kernel_end as *const _ as u64;
            let sz = e - s;
            align_up(sz, HUGE_2M as u64) + (4 * 1024 * 1024)
        }
    }

    fn setup_initial_mapping(&mut self) -> Result<(), &'static str> {
        self.map_kernel_sections()?;
        self.setup_direct_mapping()?;
        self.map_hardware_regions()?;
        self.identity_mapped = true;
        Ok(())
    }

    fn map_kernel_sections(&mut self) -> Result<(), &'static str> {
        for sec in kernel_sections().iter() {
            let pa = PhysAddr::new(sec.start - KERNEL_BASE);
            let va = VirtAddr::new(sec.start);
            let len = sec.size() as usize;

            let mut flags = VmFlags::GLOBAL;
            if sec.rw { flags |= VmFlags::RW | VmFlags::NX; } else { /* RX */ }
            if sec.nx { flags |= VmFlags::NX; }

            virt::map_range_4k_at(va, pa, len, flags).map_err(|_| "kernel section map failed")?;
            crate::log::logger::log_info!(
                "[boot_memory] map sect {:#x}-{:#x} -> {:#x} {:?}",
                sec.start, sec.end, pa.as_u64(), flags
            );
        }
        Ok(())
    }

    fn setup_direct_mapping(&mut self) -> Result<(), &'static str> {
        let size = (DIRECTMAP_SIZE.min(self.available_memory)) as usize;
        if size == 0 { return Ok(()); }
        let va = VirtAddr::new(DIRECTMAP_BASE);
        let pa = PhysAddr::new(0);
        let flags = VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL;
        virt::map_range_4k_at(va, pa, size, flags).map_err(|_| "direct map failed")?;
        crate::log::logger::log_info!(
            "[boot_memory] direct map {} MiB @ {:#x}",
            size / (1024 * 1024), DIRECTMAP_BASE
        );
        Ok(())
    }

    fn map_hardware_regions(&mut self) -> Result<(), &'static str> {
        let flags = VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD | VmFlags::PWT;

        // VGA text buffer at MMIO_BASE
        virt::map_range_4k_at(
            VirtAddr::new(MMIO_BASE),
            PhysAddr::new(0xB8000),
            PAGE_SIZE,
            flags,
        ).map_err(|_| "vga map failed")?;

        // LAPIC at MMIO_BASE + 0x1000
        virt::map_range_4k_at(
            VirtAddr::new(MMIO_BASE + 0x1000),
            PhysAddr::new(0xFEE0_0000),
            PAGE_SIZE,
            flags,
        ).map_err(|_| "lapic map failed")?;

        Ok(())
    }

    fn pte_to_vmflags(f: PageTableFlags) -> VmFlags {
        let mut vm = VmFlags::GLOBAL;
        if f.contains(PageTableFlags::WRITABLE) { vm |= VmFlags::RW | VmFlags::NX; }
        if f.contains(PageTableFlags::NO_EXECUTE) { vm |= VmFlags::NX; }
        if f.contains(PageTableFlags::USER_ACCESSIBLE) { vm |= VmFlags::USER; }
        if f.contains(PageTableFlags::from_bits_truncate(0x8)) { vm |= VmFlags::PWT; }
        if f.contains(PageTableFlags::from_bits_truncate(0x10)) { vm |= VmFlags::PCD; }
        vm
    }

    fn map_memory_range(
        &mut self,
        virt_start: VirtAddr,
        phys_start: PhysAddr,
        size: u64,
        flags: PageTableFlags,
    ) -> Result<(), &'static str> {
        let vmf = crate::memory::virt::VmFlags::Read;
        virt::map_range_4k_at(virt_start, phys_start, size as usize, vmf).map_err(|_| "map range failed")
    }

    fn allocate_page_aligned(&mut self, size: usize) -> Result<PhysAddr, &'static str> {
        let need = align_up(size as u64, PAGE_SIZE as u64);
        for r in self.regions.iter_mut() {
            if r.is_available() {
                let cur = align_up(r.start.as_u64(), PAGE_SIZE as u64);
                let end = r.end.as_u64();
                if cur + need <= end {
                    let alloc = PhysAddr::new(cur);
                    r.start = PhysAddr::new(cur + need);
                    return Ok(alloc);
                }
            }
        }
        Err("Out of memory")
    }

    pub fn get_stats(&self) -> BootMemoryStats {
        let mut stats = BootMemoryStats {
            total_regions: self.regions.len(),
            available_memory: 0,
            reserved_memory: 0,
            kernel_memory: 0,
            bootloader_memory: 0,
            hardware_memory: 0,
            total_memory: 0,
        };
        for r in &self.regions {
            let sz = r.size();
            stats.total_memory += sz;
            match r.region_type {
                BootMemoryType::Available => stats.available_memory += sz,
                BootMemoryType::Reserved => stats.reserved_memory += sz,
                BootMemoryType::Kernel => stats.kernel_memory += sz,
                BootMemoryType::Bootloader => stats.bootloader_memory += sz,
                BootMemoryType::HardwareReserved => stats.hardware_memory += sz,
                _ => stats.reserved_memory += sz,
            }
        }
        stats
    }

    pub fn dump_memory_map(&self) {
        crate::log::logger::log_info!("Memory Map:");
        for (i, r) in self.regions.iter().enumerate() {
            crate::log::logger::log_info!(
                "[boot_memory] {:2}: {:#016x}-{:#016x} {:>8} KiB {:?}",
                i,
                r.start.as_u64(),
                r.end.as_u64(),
                r.size() / 1024,
                r.region_type
            );
        }
        let s = self.get_stats();
        crate::log::logger::log_info!(
            "[boot_memory] Stats: total={} MiB avail={} MiB reserved={} MiB",
            s.total_memory / (1024 * 1024),
            s.available_memory / (1024 * 1024),
            s.reserved_memory / (1024 * 1024)
        );
    }

    pub fn enable_paging(&self) -> Result<(), &'static str> {
        // Paging is managed by the kernel VM; nothing to do here.
        Ok(())
    }

    pub fn get_available_regions(&self) -> Vec<BootMemoryRegion> {
        self.regions.iter().copied().filter(|r| r.is_available()).collect()
    }

    pub fn find_region(&self, addr: PhysAddr) -> Option<&BootMemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }
}

/// Memory statistics
#[derive(Debug, Clone)]
pub struct BootMemoryStats {
    pub total_regions: usize,
    pub available_memory: u64,
    pub reserved_memory: u64,
    pub kernel_memory: u64,
    pub bootloader_memory: u64,
    pub hardware_memory: u64,
    pub total_memory: u64,
}

use spin::Mutex;
static BOOT_MEMORY_MANAGER: Mutex<Option<BootMemoryManager>> = Mutex::new(None);

pub fn init_boot_memory(handoff_addr: u64) -> Result<(), &'static str> {
    let mut g = BOOT_MEMORY_MANAGER.lock();
    if g.is_some() { return Err("boot memory already initialized"); }
    let mut m = BootMemoryManager::new();
    m.initialize_from_handoff(handoff_addr)?;
    m.dump_memory_map();
    *g = Some(m);
    crate::log::logger::log_info!("[boot_memory] initialized");
    Ok(())
}

pub fn get_boot_memory_manager() -> Option<&'static Mutex<Option<BootMemoryManager>>> {
    Some(&BOOT_MEMORY_MANAGER)
}

pub fn get_memory_stats() -> Option<BootMemoryStats> {
    let g = BOOT_MEMORY_MANAGER.lock();
    g.as_ref().map(|m| m.get_stats())
}

pub fn allocate_boot_pages(count: usize) -> Result<PhysAddr, &'static str> {
    let mut g = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref mut m) = *g {
        m.allocate_page_aligned(count * PAGE_SIZE)
    } else {
        Err("boot memory not initialized")
    }
}

pub fn enable_memory_protection() -> Result<(), &'static str> {
    let g = BOOT_MEMORY_MANAGER.lock();
    if let Some(ref m) = *g { m.enable_paging() } else { Err("boot memory not initialized") }
}
