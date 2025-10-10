// Virtual memory manager (x86_64, 4-level paging)

#![allow(dead_code)]

use core::fmt;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{
        mapper::Translate, FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags as PtF, PhysFrame,
        Size2MiB, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::memory::layout::{KERNEL_BASE, PAGE_SIZE, HUGE_2M};
use crate::memory::phys as phys;
use crate::memory::phys::{AllocFlags};
use crate::memory::proof::{audit_map, audit_protect, audit_unmap, CapTag};

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct VmFlags: u64 {
        const RW      = 1<<1;
        const USER    = 1<<2;
        const PWT     = 1<<3;
        const PCD     = 1<<4;
        const GLOBAL  = 1<<8;
        const NX      = 1<<63;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmErr {
    NotInitialized,
    NoMemory,
    Misaligned,
    Overlap,
    NotMapped,
    HugeConflict,
    BadRange,
    WxViolation,
    Unsupported,
}

impl fmt::Display for VmErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}

pub const SELFREF_SLOT: usize = 510;

#[inline]
pub fn selfref_l4_va() -> VirtAddr {
    let idx = SELFREF_SLOT as u64;
    VirtAddr::new((0xFFFFu64 << 48) | (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12))
}

pub struct AddressSpace {
    cr3_frame: PhysFrame,
    pcid: Option<u16>,
}

impl AddressSpace {
    pub unsafe fn from_root(root_phys: u64) -> Result<Self, VmErr> {
        Ok(AddressSpace { cr3_frame: PhysFrame::containing_address(PhysAddr::new(root_phys)), pcid: None })
    }
    pub unsafe fn install(&self) -> (PhysFrame, Cr3Flags) {
        let (old, flags) = Cr3::read();
        Cr3::write(self.cr3_frame, Cr3Flags::empty());
        (old, flags)
    }
    pub fn root_phys(&self) -> u64 { self.cr3_frame.start_address().as_u64() }
}

lazy_static! {
    static ref KSPACE: Mutex<Option<AddressSpace>> = Mutex::new(None);
    static ref ROOT_PT: Mutex<Option<&'static mut PageTable>> = Mutex::new(None);
}

pub unsafe fn init(root_pt_phys: u64) -> Result<(), VmErr> {
    let aspace = AddressSpace::from_root(root_pt_phys)?;
    let (_old, _flags) = aspace.install();

    let l4_va = VirtAddr::new(root_pt_phys + KERNEL_BASE);
    let root_pt: &mut PageTable = &mut *(l4_va.as_u64() as *mut PageTable);

    if root_pt[SELFREF_SLOT].is_unused() {
        root_pt[SELFREF_SLOT].set_addr(PhysAddr::new(root_pt_phys), PtF::PRESENT | PtF::WRITABLE);
    }

    *KSPACE.lock() = Some(aspace);
    *ROOT_PT.lock() = Some(root_pt);
    Ok(())
}

fn root_mut() -> Result<OffsetPageTable<'static>, VmErr> {
    let phys_offset = VirtAddr::new(KERNEL_BASE);
    let (l4_frame, _) = Cr3::read();
    let phys_addr = l4_frame.start_address();
    let virt_addr = phys_offset + phys_addr.as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    let l4_table = unsafe { &mut *page_table_ptr };
    Ok(unsafe { OffsetPageTable::new(l4_table, phys_offset) })
}

#[inline]
fn to_ptf(f: VmFlags) -> Result<PtF, VmErr> {
    if !f.contains(VmFlags::NX) && f.contains(VmFlags::RW) {
        return Err(VmErr::WxViolation);
    }
    let mut r = PtF::PRESENT;
    if f.contains(VmFlags::RW) { r |= PtF::WRITABLE; }
    if f.contains(VmFlags::USER) { r |= PtF::USER_ACCESSIBLE; }
    if f.contains(VmFlags::PWT) { r |= PtF::from_bits_truncate(0x8); }
    if f.contains(VmFlags::PCD) { r |= PtF::from_bits_truncate(0x10); }
    if f.contains(VmFlags::GLOBAL) { r |= PtF::GLOBAL; }
    if f.contains(VmFlags::NX) { r |= PtF::NO_EXECUTE; }
    Ok(r)
}

#[inline] fn is_aligned_4k(a: u64) -> bool { (a & 0xFFF) == 0 }
#[inline] fn is_aligned_2m(a: u64) -> bool { (a & ((1<<21) - 1)) == 0 }

struct PhysAllocShim;
unsafe impl FrameAllocator<Size4KiB> for PhysAllocShim {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        phys::alloc(AllocFlags::empty()).map(|f| PhysFrame::containing_address(PhysAddr::new(f.0)))
    }
}
unsafe impl FrameAllocator<Size2MiB> for PhysAllocShim {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        phys::alloc_contig(512, 512, AllocFlags::empty()).map(|f| PhysFrame::containing_address(PhysAddr::new(f.0)))
    }
}

pub fn map4k_at(va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> Result<(), VmErr> {
    if !is_aligned_4k(va.as_u64()) || !is_aligned_4k(pa.as_u64()) { return Err(VmErr::Misaligned); }
    let hw = to_ptf(flags)?;
    let mut mapper = root_mut()?;
    let page = Page::<Size4KiB>::containing_address(va);
    let frame = PhysFrame::<Size4KiB>::containing_address(pa);
    unsafe { mapper.map_to(page, frame, hw, &mut PhysAllocShim).map_err(|_| VmErr::NoMemory)?.flush(); }
    audit_map(va.as_u64(), pa.as_u64(), PAGE_SIZE as u64, flags.bits(), CapTag::empty());
    Ok(())
}

pub fn unmap4k(va: VirtAddr) -> Result<(), VmErr> {
    if !is_aligned_4k(va.as_u64()) { return Err(VmErr::Misaligned); }
    let mut mapper = root_mut()?;
    let page = Page::<Size4KiB>::containing_address(va);
    let (_frame, flush) = mapper.unmap(page).map_err(|_| VmErr::NotMapped)?;
    flush.flush();
    audit_unmap(va.as_u64(), PAGE_SIZE as u64, CapTag::empty());
    Ok(())
}

pub fn protect4k(va: VirtAddr, flags: VmFlags) -> Result<(), VmErr> {
    if !is_aligned_4k(va.as_u64()) { return Err(VmErr::Misaligned); }
    let hw = to_ptf(flags)?;
    let mut mapper = root_mut()?;
    let page = Page::<Size4KiB>::containing_address(va);
    unsafe { mapper.update_flags(page, hw).map_err(|_| VmErr::NotMapped)?.flush(); }
    audit_protect(va.as_u64(), PAGE_SIZE as u64, flags.bits(), CapTag::empty());
    Ok(())
}

pub fn map2m_at(va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> Result<(), VmErr> {
    if !is_aligned_2m(va.as_u64()) || !is_aligned_2m(pa.as_u64()) { return Err(VmErr::Misaligned); }
    let hw = to_ptf(flags)? | PtF::HUGE_PAGE;
    let mut mapper = root_mut()?;
    unsafe {
        let page = Page::<Size2MiB>::containing_address(va);
        let frame = PhysFrame::<Size2MiB>::containing_address(pa);
        mapper.map_to(page, frame, hw, &mut PhysAllocShim).map_err(|_| VmErr::NoMemory)?.flush();
    }
    audit_map(va.as_u64(), pa.as_u64(), HUGE_2M as u64, flags.bits(), CapTag::empty());
    Ok(())
}

pub fn unmap2m(va: VirtAddr) -> Result<(), VmErr> {
    if !is_aligned_2m(va.as_u64()) { return Err(VmErr::Misaligned); }
    let mut mapper = root_mut()?;
    unsafe {
        let page = Page::<Size2MiB>::containing_address(va);
        match mapper.unmap(page) {
            Ok((_frame, flush)) => {
                flush.flush();
                audit_unmap(va.as_u64(), HUGE_2M as u64, CapTag::empty());
                Ok(())
            }
            Err(_) => {
                // Fallback: unmap 4K range
                let start4k = Page::<Size4KiB>::containing_address(va);
                for i in 0..(HUGE_2M / PAGE_SIZE) {
                    let va4k = VirtAddr::new(start4k.start_address().as_u64() + (i * PAGE_SIZE) as u64);
                    let _ = unmap4k(va4k);
                }
                audit_unmap(va.as_u64(), HUGE_2M as u64, CapTag::empty());
                Ok(())
            }
        }
    }
}

pub fn map_range_4k_at(base: VirtAddr, pa: PhysAddr, len: usize, flags: VmFlags) -> Result<(), VmErr> {
    if len == 0 || !is_aligned_4k(base.as_u64()) || !is_aligned_4k(pa.as_u64()) { return Err(VmErr::Misaligned); }
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    for p in 0..pages {
        map4k_at(
            VirtAddr::new(base.as_u64() + (p * PAGE_SIZE) as u64),
            PhysAddr::new(pa.as_u64() + (p * PAGE_SIZE) as u64),
            flags,
        )?;
    }
    Ok(())
}

pub fn unmap_range_4k(base: VirtAddr, len: usize) -> Result<(), VmErr> {
    if len == 0 || !is_aligned_4k(base.as_u64()) { return Err(VmErr::Misaligned); }
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    for p in 0..pages {
        unmap4k(VirtAddr::new(base.as_u64() + (p * PAGE_SIZE) as u64))?;
    }
    Ok(())
}

pub fn protect_range_4k(base: VirtAddr, len: usize, flags: VmFlags) -> Result<(), VmErr> {
    if len == 0 || !is_aligned_4k(base.as_u64()) { return Err(VmErr::Misaligned); }
    for off in (0..len).step_by(PAGE_SIZE) {
        protect4k(VirtAddr::new(base.as_u64() + off as u64), flags)?;
    }
    Ok(())
}

pub fn translate(va: VirtAddr) -> Result<(PhysAddr, VmFlags, usize), VmErr> {
    let mapper = root_mut()?;
    if let Some(pa) = mapper.translate_addr(va) {
        let (flags, page_size) = unsafe {
            let (l4_frame, _) = Cr3::read();
            let l4_phys = l4_frame.start_address();
            let l4_virt = VirtAddr::new(KERNEL_BASE + l4_phys.as_u64());
            let l4: &PageTable = &*(l4_virt.as_ptr() as *const PageTable);

            let l4i = ((va.as_u64() >> 39) & 0x1ff) as usize;
            let l3i = ((va.as_u64() >> 30) & 0x1ff) as usize;
            let l2i = ((va.as_u64() >> 21) & 0x1ff) as usize;
            let l1i = ((va.as_u64() >> 12) & 0x1ff) as usize;

            if l4[l4i].is_unused() { return Err(VmErr::NotMapped); }
            let l3p = l4[l4i].addr();
            let l3: &PageTable = &*(VirtAddr::new(KERNEL_BASE + l3p.as_u64()).as_ptr() as *const PageTable);

            if l3[l3i].is_unused() { return Err(VmErr::NotMapped); }
            let l2p = l3[l3i].addr();
            let l2: &PageTable = &*(VirtAddr::new(KERNEL_BASE + l2p.as_u64()).as_ptr() as *const PageTable);

            if l2[l2i].is_unused() { return Err(VmErr::NotMapped); }
            if l2[l2i].flags().contains(PtF::HUGE_PAGE) {
                (vmflags_from_ptf(l2[l2i].flags()), HUGE_2M)
            } else {
                let l1p = l2[l2i].addr();
                let l1: &PageTable = &*(VirtAddr::new(KERNEL_BASE + l1p.as_u64()).as_ptr() as *const PageTable);
                if l1[l1i].is_unused() { return Err(VmErr::NotMapped); }
                (vmflags_from_ptf(l1[l1i].flags()), PAGE_SIZE)
            }
        };
        Ok((pa, flags, page_size))
    } else {
        Err(VmErr::NotMapped)
    }
}

fn vmflags_from_ptf(p: PtF) -> VmFlags {
    let mut f = VmFlags::empty();
    if p.contains(PtF::WRITABLE) { f |= VmFlags::RW; }
    if p.contains(PtF::USER_ACCESSIBLE) { f |= VmFlags::USER; }
    if p.bits() & 0x8 != 0 { f |= VmFlags::PWT; }
    if p.bits() & 0x10 != 0 { f |= VmFlags::PCD; }
    if p.contains(PtF::GLOBAL) { f |= VmFlags::GLOBAL; }
    if p.contains(PtF::NO_EXECUTE) { f |= VmFlags::NX; }
    f
}

pub fn gc_tables() -> Result<(), VmErr> { Ok(()) }

pub fn tlb_shootdown_local() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

pub struct MapCtx;
impl MapCtx {
    #[inline] pub fn root() -> Result<OffsetPageTable<'static>, VmErr> { root_mut() }
}

pub fn assert_wx_exclusive(range_base: VirtAddr, len: usize) -> Result<(), VmErr> {
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    for p in 0..pages {
        let va = VirtAddr::new(range_base.as_u64() + (p * PAGE_SIZE) as u64);
        if let Ok((_pa, fl, _sz)) = translate(va) {
            let x = !fl.contains(VmFlags::NX);
            let w = fl.contains(VmFlags::RW);
            if x && w { return Err(VmErr::WxViolation); }
        }
    }
    Ok(())
}

pub fn init_from_bootinfo(_boot_info: &'static bootloader_api::BootInfo) {
    // Root table init should be performed by platform code; keep as NOP here.
}

pub fn get_kernel_mapper() -> Result<OffsetPageTable<'static>, VmErr> { root_mut() }

pub fn dump<F>(mut writer: F)
where
    F: FnMut(&str),
{
    writer("vm: online\n");
}
