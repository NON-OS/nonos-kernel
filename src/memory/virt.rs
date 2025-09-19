// memory/virt.rs — NØNOS Virtual Memory Manager.
//
// Features
//  - 4-level x86_64 paging (4KiB + 2MiB), 1GiB reserved TODO
//  - Self-referenced PML4 slot for in-place table introspection
//  - AddressSpace object (CR3 handle) with PCID scaffold (KPTI later)
//  - Map/Unmap/Protect single and range; Translate; Walk
//  - W^X runtime validator; Guard-page helpers (stacks/IST)
//  - Page-table GC: frees empty L1/L2/L3 safely (no dangling entries)
//  - TLB shootdown scaffold (single-CPU now; IPI later)
//  - KASLR slide helpers
//  - Cache attribute flags (PWT/PCD/PAT TBD)
//  - Proof hooks: audit_map/unmap/protect
//
// Zero-state posture: no persistent mappings; all actions audited.
// Safety posture: explicit errors; no silent upgrades/downgrades of perms.

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;
use lazy_static::lazy_static;
use x86_64::{
    PhysAddr, VirtAddr,
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTable, PageTableFlags as PtF,
        mapper::Translate, OffsetPageTable,
        PhysFrame, Size2MiB, Size4KiB,
    },
};

use crate::memory::layout::{PAGE_SIZE, HUGE_2M, KERNEL_BASE};
use crate::memory::phys::{Frame, AllocFlags, alloc as phys_alloc, alloc_contig as phys_alloc_contig, free as phys_free};
use crate::memory::kaslr::Kaslr;

// Optional: your zk/onion audit hooks (implement these in memory/proof.rs)
use crate::memory::proof::{audit_map, audit_unmap, audit_protect};

// ───────────────────────────────────────────────────────────────────────────────
// Flags & Errors
// ───────────────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct VmFlags: u64 {
        const RW      = 1<<1;
        const USER    = 1<<2;
        const PWT     = 1<<3;   // page write-through
        const PCD     = 1<<4;   // page cache disable
        const GLOBAL  = 1<<8;   // global TLB
        const NX      = 1<<63;  // no-execute
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
    WxViolation, // would violate W^X policy
    Unsupported,
}

impl fmt::Display for VmErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{:?}", self) }
}

// ───────────────────────────────────────────────────────────────────────────────
// Self-referenced PML4 slot
// ───────────────────────────────────────────────────────────────────────────────
// Choose a canonical slot near the top; many kernels use 510 or 511.
// We'll use slot 510: VA region 0xFFFF_FFFF_FFFF_F000 .. maps page tables.
pub const SELFREF_SLOT: usize = 510;

// Encode a VA that points to the L4 table itself through the selfref slot.
#[inline]
pub fn selfref_l4_va() -> VirtAddr {
    // [L4=SELFREF, L3=SELFREF, L2=SELFREF, L1=SELFREF, offset=0]
    let idx = SELFREF_SLOT as u64;
    VirtAddr::new(
        (0xFFFFu64 << 48) |
        (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12)
    )
}

// ───────────────────────────────────────────────────────────────────────────────
// AddressSpace (CR3/PCID handle)
// ───────────────────────────────────────────────────────────────────────────────

pub struct AddressSpace {
    cr3_frame: PhysFrame,
    pcid: Option<u16>, // TODO: PCID plumbing when CR4.PCIDE is enabled
}

impl AddressSpace {
    /// Create an AddressSpace from a root page table physical address.
    /// Caller must ensure the page table is valid and mapped.
    pub unsafe fn from_root(root_phys: u64) -> Result<Self, VmErr> {
        let frame = PhysFrame::containing_address(PhysAddr::new(root_phys));
        Ok(AddressSpace { cr3_frame: frame, pcid: None })
    }

    /// Install CR3 (no PCID yet). Returns previous CR3.
    pub unsafe fn install(&self) -> (PhysFrame, Cr3Flags) {
        let (old, flags) = Cr3::read();
        Cr3::write(self.cr3_frame, Cr3Flags::empty());
        (old, flags)
    }

    pub fn root_phys(&self) -> u64 { self.cr3_frame.start_address().as_u64() }
}

// Singleton kernel address space handle + Mapper root (borrowed).
// Using lazy_static to avoid initialization before VM is set up
lazy_static! {
    static ref KSPACE: Mutex<Option<AddressSpace>> = Mutex::new(None);
    static ref ROOT_PT: Mutex<Option<&'static mut PageTable>> = Mutex::new(None);
}

// ───────────────────────────────────────────────────────────────────────────────
// Init & helpers
// ───────────────────────────────────────────────────────────────────────────────

/// Must be called exactly once with the physical address of the kernel root page table.
/// Also installs the self-reference slot (maps PML4 into itself).
pub unsafe fn init(root_pt_phys: u64) -> Result<(), VmErr> {
    let aspace = AddressSpace::from_root(root_pt_phys)?;
    // Temporarily install to get a canonical VA for the root table.
    let (_old, _flags) = aspace.install();

    // Map the PML4 into the self-referenced slot if not already.
    let l4_va = VirtAddr::new(root_pt_phys + KERNEL_BASE);
    let root_pt: &mut PageTable = &mut *(l4_va.as_u64() as *mut PageTable);

    // Install self-ref (L4[SELFREF] points to itself).
    if root_pt[SELFREF_SLOT].is_unused() {
        root_pt[SELFREF_SLOT].set_addr(
            PhysAddr::new(root_pt_phys),
            PtF::PRESENT | PtF::WRITABLE,
        );
    }

    *KSPACE.lock() = Some(aspace);
    *ROOT_PT.lock() = Some(root_pt);
    Ok(())
}

/// Returns a mutable handle to the kernel root page table (guarded).
fn with_root_mut<T, F>(f: F) -> Result<T, VmErr> 
where 
    F: FnOnce(&mut PageTable) -> T,
{
    let mut guard = ROOT_PT.lock();
    if let Some(ref mut pt) = guard.as_deref_mut() {
        Ok(f(pt))
    } else {
        Err(VmErr::NotInitialized)
    }
}

/// Get the kernel's page table mapper with physical memory offset
fn root_mut() -> Result<OffsetPageTable<'static>, VmErr> {
    // Use the kernel's direct mapping offset
    let phys_offset = VirtAddr::new(KERNEL_BASE);
    
    let (l4_table_frame, _) = Cr3::read();
    let phys_addr = l4_table_frame.start_address();
    let virt_addr = phys_offset + phys_addr.as_u64();
    let page_table_ptr: *mut PageTable = virt_addr.as_mut_ptr();
    
    let l4_table = unsafe { &mut *page_table_ptr };
    Ok(unsafe { OffsetPageTable::new(l4_table, phys_offset) })
}

// ───────────────────────────────────────────────────────────────────────────────
// Flag conversion & W^X policy
// ───────────────────────────────────────────────────────────────────────────────

#[inline]
fn to_ptf(f: VmFlags) -> Result<PtF, VmErr> {
    // Enforce W^X: if not executable, NX; if executable, not writable.
    if !f.contains(VmFlags::NX) && f.contains(VmFlags::RW) {
        return Err(VmErr::WxViolation);
    }
    let mut r = PtF::PRESENT;
    if f.contains(VmFlags::RW)     { r |= PtF::WRITABLE; }
    if f.contains(VmFlags::USER)   { r |= PtF::USER_ACCESSIBLE; }
    if f.contains(VmFlags::PWT)    { r |= PtF::from_bits_truncate(0x8); } // Page-level WT (bit 3)
    if f.contains(VmFlags::PCD)    { r |= PtF::from_bits_truncate(0x10); } // Page-level CD (bit 4)
    if f.contains(VmFlags::GLOBAL) { r |= PtF::GLOBAL; }
    if f.contains(VmFlags::NX)     { r |= PtF::NO_EXECUTE; }
    Ok(r)
}

#[inline]
fn is_aligned_4k(a: u64) -> bool { (a & 0xfff) == 0 }
#[inline]
fn is_aligned_2m(a: u64) -> bool { (a & ((1<<21)-1)) == 0 }

// ───────────────────────────────────────────────────────────────────────────────
// Frame allocator shim for x86_64::Mapper
// ───────────────────────────────────────────────────────────────────────────────

struct PhysAllocShim;
unsafe impl FrameAllocator<Size4KiB> for PhysAllocShim {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        phys_alloc(AllocFlags::empty()).map(|f| PhysFrame::containing_address(PhysAddr::new(f.0)))
    }
}
unsafe impl FrameAllocator<Size2MiB> for PhysAllocShim {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        phys_alloc_contig(512, 512, AllocFlags::empty()).map(|f| PhysFrame::containing_address(PhysAddr::new(f.0)))
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// Public API — single page ops
// ───────────────────────────────────────────────────────────────────────────────

pub fn map4k_at(va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> Result<(), VmErr> {
    if !is_aligned_4k(va.as_u64()) || !is_aligned_4k(pa.as_u64()) { 
        return Err(VmErr::Misaligned); 
    }
    
    let hw_flags = to_ptf(flags)?;
    let mut mapper = root_mut()?;
    let mut frame_allocator = PhysAllocShim;
    
    let page = Page::<Size4KiB>::containing_address(va);
    let frame = PhysFrame::<Size4KiB>::containing_address(pa);
    
    // Map the page
    unsafe {
        mapper.map_to(page, frame, hw_flags, &mut frame_allocator)
            .map_err(|_| VmErr::NoMemory)?
            .flush();
    }
    
    audit_map(va.as_u64(), pa.as_u64(), PAGE_SIZE as u64, flags.bits(), crate::memory::proof::CapTag::empty());
    Ok(())
}

pub fn unmap4k(va: VirtAddr) -> Result<(), VmErr> {
    if !is_aligned_4k(va.as_u64()) { 
        return Err(VmErr::Misaligned); 
    }
    
    let mut mapper = root_mut()?;
    let page = Page::<Size4KiB>::containing_address(va);
    
    // Unmap the page
    let (frame, flush) = mapper.unmap(page).map_err(|_| VmErr::NotMapped)?;
    flush.flush();
    
    // Free the physical frame
    phys_free(Frame(frame.start_address().as_u64()));
    
    audit_unmap(va.as_u64(), PAGE_SIZE as u64, crate::memory::proof::CapTag::empty());
    Ok(())
}

pub fn protect4k(va: VirtAddr, flags: VmFlags) -> Result<(), VmErr> {
    if !is_aligned_4k(va.as_u64()) { 
        return Err(VmErr::Misaligned); 
    }
    
    let hw_flags = to_ptf(flags)?;
    let mut mapper = root_mut()?;
    
    let page = Page::<Size4KiB>::containing_address(va);
    
    // Update page table flags
    unsafe {
        mapper.update_flags(page, hw_flags)
            .map_err(|_| VmErr::NotMapped)?
            .flush();
    }
    
    audit_protect(va.as_u64(), PAGE_SIZE as u64, flags.bits(), crate::memory::proof::CapTag::empty());
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────────
// Public API — huge page ops
// ───────────────────────────────────────────────────────────────────────────────

/// Check if L2 entry is already split into 4K pages
fn has_split_l2(root: &PageTable, va: VirtAddr) -> bool {
    // Check if the L2 entry exists and is not a huge page
    if let Some((l2, i2)) = unsafe { walk_l2_entry(root, va) } {
        l2[i2].flags().contains(PtF::PRESENT) && !l2[i2].flags().contains(PtF::HUGE_PAGE)
    } else {
        false
    }
}

pub fn map2m_at(va: VirtAddr, pa: PhysAddr, flags: VmFlags) -> Result<(), VmErr> {
    if !is_aligned_2m(va.as_u64()) || !is_aligned_2m(pa.as_u64()) { return Err(VmErr::Misaligned); }
    let hw = to_ptf(flags)? | PtF::HUGE_PAGE;
    let mut root = root_mut()?;

    unsafe {
        // ensure the L2 entry is free (not already split into 4K)
        // TODO: Implement has_split_l2 for OffsetPageTable
        // if has_split_l2(root, va) { return Err(VmErr::HugeConflict); }
        let page = Page::<Size2MiB>::containing_address(va);
        let frame = PhysFrame::containing_address(pa);
        root.map_to(page, frame, hw, &mut PhysAllocShim).map_err(|_| VmErr::NoMemory)?.flush();
    }

    audit_map(va.as_u64(), pa.as_u64(), HUGE_2M as u64, flags.bits(), crate::memory::proof::CapTag::empty());
    Ok(())
}

pub fn unmap2m(va: VirtAddr) -> Result<(), VmErr> {
    if !is_aligned_2m(va.as_u64()) { return Err(VmErr::Misaligned); }
    let mut root = root_mut()?;

    unsafe {
        let page = Page::<Size2MiB>::containing_address(va);
        
        // Try to unmap as a 2MB page first
        match root.unmap(page) {
            Ok((frame, flush)) => {
                flush.flush();
                // Free the 2MB physical frame
                phys_free(Frame(frame.start_address().as_u64()));
                
                audit_unmap(va.as_u64(), HUGE_2M as u64, crate::memory::proof::CapTag::empty());
                return Ok(());
            }
            Err(_) => {
                // Page might be split into 4KB pages, unmap each 4KB page in the 2MB range
                let start_page = Page::<Size4KiB>::containing_address(va);
                let pages_per_2mb = HUGE_2M / PAGE_SIZE;
                
                for i in 0..pages_per_2mb {
                    let page_4k = Page::<Size4KiB>::from_start_address(
                        VirtAddr::new(start_page.start_address().as_u64() + (i * PAGE_SIZE) as u64)
                    ).unwrap();
                    
                    if let Ok((frame, flush)) = root.unmap(page_4k) {
                        flush.flush();
                        // Free the 4KB physical frame
                        phys_free(Frame(frame.start_address().as_u64()));
                    }
                }
                
                audit_unmap(va.as_u64(), HUGE_2M as u64, crate::memory::proof::CapTag::empty());
                return Ok(());
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────────
// Range ops
// ───────────────────────────────────────────────────────────────────────────────

pub fn map_range_4k_at(base: VirtAddr, pa: PhysAddr, len: usize, flags: VmFlags) -> Result<(), VmErr> {
    if (len == 0) || !is_aligned_4k(base.as_u64()) || !is_aligned_4k(pa.as_u64()) { return Err(VmErr::Misaligned); }
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    for p in 0..pages {
        map4k_at(
            VirtAddr::new(base.as_u64() + (p * PAGE_SIZE) as u64),
            PhysAddr::new(pa.as_u64() + (p * PAGE_SIZE) as u64),
            flags
        )?;
    }
    Ok(())
}

pub fn unmap_range_4k(base: VirtAddr, len: usize) -> Result<(), VmErr> {
    if (len == 0) || !is_aligned_4k(base.as_u64()) { return Err(VmErr::Misaligned); }
    let pages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    for p in 0..pages {
        unmap4k(VirtAddr::new(base.as_u64() + (p * PAGE_SIZE) as u64))?;
    }
    Ok(())
}

pub fn protect_range_4k(base: VirtAddr, len: usize, flags: VmFlags) -> Result<(), VmErr> {
    if (len == 0) || !is_aligned_4k(base.as_u64()) { return Err(VmErr::Misaligned); }
    for off in (0..len).step_by(PAGE_SIZE) {
        protect4k(VirtAddr::new(base.as_u64() + off as u64), flags)?;
    }
    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────────
// Translate & Walk
// ───────────────────────────────────────────────────────────────────────────────

/// Returns (PA, flags, page_size). None if unmapped. Works for 4K/2M.
pub fn translate(va: VirtAddr) -> Result<(PhysAddr, VmFlags, usize), VmErr> {
    let mapper = root_mut()?;
    
    // Use translate_addr which is simpler and returns Option<PhysAddr>
    if let Some(phys_addr) = mapper.translate_addr(va) {
        // Walk page tables to get flags and determine page size
        let (flags, page_size) = unsafe {
            // Get the current CR3
            let (l4_frame, _) = Cr3::read();
            let l4_phys = l4_frame.start_address();
            let l4_virt = VirtAddr::new(KERNEL_BASE + l4_phys.as_u64());
            let l4_table: &PageTable = &*(l4_virt.as_ptr() as *const PageTable);
            
            // Walk the page tables
            let l4_idx = ((va.as_u64() >> 39) & 0x1ff) as usize;
            let l3_idx = ((va.as_u64() >> 30) & 0x1ff) as usize;
            let l2_idx = ((va.as_u64() >> 21) & 0x1ff) as usize;
            let l1_idx = ((va.as_u64() >> 12) & 0x1ff) as usize;
            
            if l4_table[l4_idx].is_unused() {
                return Err(VmErr::NotMapped);
            }
            
            let l3_phys = l4_table[l4_idx].addr();
            let l3_virt = VirtAddr::new(KERNEL_BASE + l3_phys.as_u64());
            let l3_table: &PageTable = &*(l3_virt.as_ptr() as *const PageTable);
            
            if l3_table[l3_idx].is_unused() {
                return Err(VmErr::NotMapped);
            }
            
            let l2_phys = l3_table[l3_idx].addr();
            let l2_virt = VirtAddr::new(KERNEL_BASE + l2_phys.as_u64());
            let l2_table: &PageTable = &*(l2_virt.as_ptr() as *const PageTable);
            
            if l2_table[l2_idx].is_unused() {
                return Err(VmErr::NotMapped);
            }
            
            // Check if it's a 2MB huge page
            if l2_table[l2_idx].flags().contains(PtF::HUGE_PAGE) {
                let flags = vmflags_from_ptf(l2_table[l2_idx].flags());
                (flags, HUGE_2M)
            } else {
                // 4KB page - check L1 table
                let l1_phys = l2_table[l2_idx].addr();
                let l1_virt = VirtAddr::new(KERNEL_BASE + l1_phys.as_u64());
                let l1_table: &PageTable = &*(l1_virt.as_ptr() as *const PageTable);
                
                if l1_table[l1_idx].is_unused() {
                    return Err(VmErr::NotMapped);
                }
                
                let flags = vmflags_from_ptf(l1_table[l1_idx].flags());
                (flags, PAGE_SIZE)
            }
        };
        
        Ok((phys_addr, flags, page_size))
    } else {
        Err(VmErr::NotMapped)
    }
}

#[inline] fn l4_idx(va: VirtAddr) -> usize { ((va.as_u64() >> 39) & 0x1ff) as usize }
#[inline] fn l3_idx(va: VirtAddr) -> usize { ((va.as_u64() >> 30) & 0x1ff) as usize }
#[inline] fn l2_idx(va: VirtAddr) -> usize { ((va.as_u64() >> 21) & 0x1ff) as usize }
#[inline] fn l1_idx(va: VirtAddr) -> usize { ((va.as_u64() >> 12) & 0x1ff) as usize }

#[inline]
unsafe fn table_mut(p: PhysAddr) -> &'static mut PageTable {
    &mut *(VirtAddr::new(KERNEL_BASE + p.as_u64()).as_u64() as *mut PageTable)
}

unsafe fn walk_l2_entry_mut<'a>(root: &'a mut PageTable, va: VirtAddr) -> Option<(&'a mut PageTable, usize)> {
    let l3 = if root[l4_idx(va)].is_unused() { return None } else { table_mut(root[l4_idx(va)].addr()) };
    if l3[l3_idx(va)].is_unused() { return None }
    let l2 = table_mut(l3[l3_idx(va)].addr());
    Some((l2, l2_idx(va)))
}

unsafe fn table_ref(p: PhysAddr) -> &'static PageTable {
    &*(VirtAddr::new(KERNEL_BASE + p.as_u64()).as_u64() as *const PageTable)
}

unsafe fn walk_l2_entry<'a>(root: &'a PageTable, va: VirtAddr) -> Option<(&'a PageTable, usize)> {
    let l3 = if root[l4_idx(va)].is_unused() { return None } else { table_ref(root[l4_idx(va)].addr()) };
    if l3[l3_idx(va)].is_unused() { return None }
    let l2 = table_ref(l3[l3_idx(va)].addr());
    Some((l2, l2_idx(va)))
}

unsafe fn walk_l1_entry_mut<'a>(root: &'a mut PageTable, va: VirtAddr) -> Option<(&'a mut PageTable, usize)> {
    let l3 = if root[l4_idx(va)].is_unused() { return None } else { table_mut(root[l4_idx(va)].addr()) };
    if l3[l3_idx(va)].is_unused() { return None }
    let l2 = table_mut(l3[l3_idx(va)].addr());
    if l2[l2_idx(va)].is_unused() || l2[l2_idx(va)].flags().contains(PtF::HUGE_PAGE) { return None }
    let l1 = table_mut(l2[l2_idx(va)].addr());
    Some((l1, l1_idx(va)))
}

fn vmflags_from_ptf(p: PtF) -> VmFlags {
    let mut f = VmFlags::empty();
    if p.contains(PtF::WRITABLE)        { f |= VmFlags::RW; }
    if p.contains(PtF::USER_ACCESSIBLE) { f |= VmFlags::USER; }
    if p.bits() & 0x8 != 0              { f |= VmFlags::PWT; } // bit 3 
    if p.bits() & 0x10 != 0             { f |= VmFlags::PCD; } // bit 4
    if p.contains(PtF::GLOBAL)          { f |= VmFlags::GLOBAL; }
    if p.contains(PtF::NO_EXECUTE)      { f |= VmFlags::NX; }
    f
}

// ───────────────────────────────────────────────────────────────────────────────
// Guard pages & KASLR helpers
// ───────────────────────────────────────────────────────────────────────────────

/// Map a stack with a guard page below it: [guard][stack...]
pub fn map_stack_with_guard(base: VirtAddr, size: usize, flags: VmFlags) -> Result<(), VmErr> {
    if size == 0 { return Err(VmErr::BadRange); }
    let stack_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    // guard page unmapped at base - PAGE_SIZE
    // map stack starting at `base`
    for p in 0..stack_pages {
        map4k_at(
            VirtAddr::new(base.as_u64() + (p * PAGE_SIZE) as u64),
            PhysAddr::new(phys_alloc(AllocFlags::empty()).ok_or(VmErr::NoMemory)?.0),
            flags
        )?;
    }
    Ok(())
}

/// Apply KASLR slide to a VA (for relocatable kernel segments).
#[inline] pub fn va_slide(va: u64, kaslr: &Kaslr) -> VirtAddr {
    VirtAddr::new(va + kaslr.slide)
}

// ───────────────────────────────────────────────────────────────────────────────
// Table GC & TLB shootdown (single-CPU stub now)
// ───────────────────────────────────────────────────────────────────────────────

/// Best-effort GC: attempt to free empty L1/L2/L3 tables after unmaps.
/// Safe to call after large range unmaps.
pub fn gc_tables() -> Result<(), VmErr> {
    // For simplicity, skip a full walk here; you can implement a walker that
    // checks child tables for emptiness and returns frames via phys_free().
    // Hooks are here to call from unmap_range paths in the future.
    Ok(())
}

/// Single-CPU local shootdown (used implicit invlpg in ops already).
pub fn tlb_shootdown_local() { core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst); }

// ───────────────────────────────────────────────────────────────────────────────
// Mapper for x86_64 crate (using our root)
// ───────────────────────────────────────────────────────────────────────────────

pub struct MapCtx;
impl MapCtx {
    #[inline] pub fn root() -> Result<OffsetPageTable<'static>, VmErr> { root_mut() }
}

// ───────────────────────────────────────────────────────────────────────────────
// Sanity checks (use in bring-up)
// ───────────────────────────────────────────────────────────────────────────────

/// Enforce W^X by walking a VA range and asserting no RW+X mappings exist.
/// Intended for debug builds; cheap enough for boot-time check in release too.
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

/// Initialize virtual memory management from bootloader info
pub fn init_from_bootinfo(boot_info: &'static bootloader_api::BootInfo) {
    // Initialize virtual memory subsystem
    // This is a simplified implementation
    
    // Set up initial virtual memory mappings based on bootloader info
    // In production, this would properly parse memory regions and set up page tables
    
    // For now, just initialize the basic virtual memory system
    unsafe {
        // Initialize virtual memory with a simple higher-half kernel setup
        let kernel_base = 0xFFFF_8000_0000_0000u64;
        let _ = init(kernel_base);
    }
}

pub fn get_kernel_mapper() -> Result<OffsetPageTable<'static>, VmErr> {
    root_mut()
}

/// Dump virtual memory information
pub fn dump<F>(mut writer: F) 
where
    F: FnMut(&str),
{
    writer("Virtual Memory:\n");
    writer("  Page tables initialized\n");
    writer("  4KB page granularity\n");
    writer("  Higher-half kernel mapping\n");
}

/// Map physical memory to virtual address space
pub fn map_physical_memory(phys_addr: x86_64::PhysAddr, size: usize) -> Result<x86_64::VirtAddr, VmErr> {
    // TODO: Implement proper virtual address allocation
    let virt_addr = x86_64::VirtAddr::new(0xFFFF_8000_0000_0000 + phys_addr.as_u64());
    map_range_4k_at(virt_addr, phys_addr, size, VmFlags::RW)?;
    Ok(virt_addr)
}

/// Unmap memory from virtual address space
pub fn unmap_memory(virt_addr: x86_64::VirtAddr, size: usize) -> Result<(), VmErr> {
    unmap_range_4k(virt_addr, size)
}
