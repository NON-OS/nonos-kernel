// kernel/src/memory/mmio.rs
// eK@nonos-tech.xyz
//
// Device MMIO mapping (PAT-aware) for NØNOS.
//
// - ioremap/iounmap with region registry (overlap checks, refcount, labels)
// - Cache types: UC, UC_MINUS, WC, WT, WB (PAT indices), with safe fallback
// - RW+NX always; W^X enforced at VMM
// - Barriers: lfence/sfence/mfence; posted-write flush helpers (readback fence)
// - MSI/MSI-X helpers (mask/unmask/vector write) with ordering guarantees
// - Probe map/unmap; retype() to adjust cache type post-PAT init
// - Proof hooks (DMA/KERNEL) on map/unmap
//
// PAT setup is platform code elsewhere; we just consume PAT indices that
// platform exposes via get_pat_index(). If not ready, we fall back to UC.
//
// Zero-state: no persistence; registry lives in RAM only.

#![allow(dead_code)]

use core::{marker::PhantomData, ptr};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::layout::PAGE_SIZE;
use crate::memory::virt::{self, VmFlags};
use crate::memory::proof::{self, CapTag};

/// CPU-ordering helpers
#[inline(always)] pub fn lfence() { unsafe { core::arch::asm!("lfence", options(nomem, nostack, preserves_flags)) } }
#[inline(always)] pub fn sfence() { unsafe { core::arch::asm!("sfence", options(nomem, nostack, preserves_flags)) } }
#[inline(always)] pub fn mfence() { unsafe { core::arch::asm!("mfence", options(nomem, nostack, preserves_flags)) } }

/// PAT cache kinds we expose at the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheKind { UC, UcMinus, WC, WT, WB }

/// Alias for compatibility
pub type CacheAttr = CacheKind;

/// Platform hook: return PTE bits for the PAT type at L1.
/// If `None`, callers should fall back to UC.
pub fn pat_flags_for(kind: CacheKind) -> Option<VmFlags> {
    // NOTE: this is a placeholder. When PAT is configured, translate PAT index
    // into PTE (PAT/PWT/PCD) bits and OR them into VmFlags via virt layer.
    match kind {
        CacheKind::UC       => Some(VmFlags::PCD),                         // PCD=1 PWT=0
        CacheKind::UcMinus => Some(VmFlags::PCD | VmFlags::PWT),          // UC- (device-like)
        CacheKind::WT       => Some(VmFlags::PWT),                         // WT
        CacheKind::WB       => Some(VmFlags::empty()),                     // WB default
        CacheKind::WC       => None, // until PAT WC index is actually programmed
    }
}

/// Registry entry for live MMIO windows.
#[derive(Clone, Copy)]
struct Region {
    base_va: u64,
    base_pa: u64,
    len:     usize,
    flags:   VmFlags,
    refs:    u32,
    label:   [u8; 16], // short tag (PCI BDF, device id, etc.)
}

const MAX_MMIO: usize = 128;
static REG: Mutex<[Option<Region>; MAX_MMIO]> = Mutex::new([None; MAX_MMIO]);

fn reg_insert(r: Region) -> Result<usize, ()> {
    let mut t = REG.lock();
    // overlap guard
    for e in t.iter().flatten() {
        let a0 = r.base_va; let a1 = r.base_va + r.len as u64;
        let b0 = e.base_va; let b1 = e.base_va + e.len as u64;
        if a0 < b1 && b0 < a1 { return Err(()); }
    }
    for (i, slot) in t.iter_mut().enumerate() {
        if slot.is_none() { *slot = Some(r); return Ok(i); }
    }
    Err(())
}

fn reg_find(va: u64) -> Option<usize> {
    let t = REG.lock();
    for (i, e) in t.iter().enumerate() {
        if let Some(r) = e {
            if va >= r.base_va && va < r.base_va + r.len as u64 { return Some(i); }
        }
    }
    None
}

fn reg_remove(idx: usize) -> Region {
    let mut t = REG.lock();
    let r = t[idx].take().expect("mmio: missing reg");
    r
}

fn reg_addref(idx: usize) {
    let mut t = REG.lock();
    if let Some(r) = &mut t[idx] { r.refs = r.refs.saturating_add(1); }
}

fn reg_set_label(idx: usize, label: &str) {
    let mut t = REG.lock();
    if let Some(r) = &mut t[idx] {
        let bytes = label.as_bytes();
        let n = bytes.len().min(16);
        r.label[..n].copy_from_slice(&bytes[..n]);
        for b in &mut r.label[n..] { *b = 0; }
    }
}

fn vmflags_for(kind: CacheKind) -> VmFlags {
    // Always kernel RW+NX, GLOBAL. Cache attrs via PAT/PWT/PCD.
    let base = VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL;
    match pat_flags_for(kind).or_else(|| pat_flags_for(CacheKind::UC)) {
        Some(extra) => base | extra,
        None => base | VmFlags::PCD, // safe fallback
    }
}

/// A mapped MMIO window. Not Send/Sync by default.
pub struct Mmio {
    base: VirtAddr,
    len:  usize,
    idx:  usize,                 // registry index
    _nosend: PhantomData<*mut ()>,
}

impl Mmio {
    /// Map [pa, pa+len) with requested cache kind.
    /// Returns a handle with refcounted registry entry.
    ///
    /// Safety: caller guarantees the physical region is a device MMIO BAR or
    /// ACPI/firmware table; not regular RAM.
    pub unsafe fn ioremap(pa: PhysAddr, len: usize, kind: CacheKind, label: &str) -> Result<Self, ()> {
        if len == 0 { return Err(()); }
        let off = (pa.as_u64() & (PAGE_SIZE as u64 - 1)) as usize;
        let pa_aln = PhysAddr::new(pa.as_u64() & !((PAGE_SIZE as u64) - 1));
        let total = off + len;
        let pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;

        let flags = vmflags_for(kind);
        let base = map_mmio_pages(pa_aln, pages, flags).map_err(|_| ())?;
        proof::audit_map(base.as_u64(), pa_aln.as_u64(), (pages * PAGE_SIZE) as u64, flags.bits(), CapTag::DMA | CapTag::KERNEL);

        let idx = reg_insert(Region {
            base_va: base.as_u64() + off as u64,
            base_pa: pa.as_u64(),
            len,
            flags,
            refs: 1,
            label: [0;16],
        })?;
        reg_set_label(idx, label);

        Ok(Self { base: VirtAddr::new(base.as_u64() + off as u64), len, idx, _nosend: PhantomData })
    }

    /// Duplicate handle (bumps refcount).
    pub fn clone_ref(&self) -> Self {
        reg_addref(self.idx);
        Self { base: self.base, len: self.len, idx: self.idx, _nosend: PhantomData }
    }

    /// Unmap when last reference drops.
    pub unsafe fn iounmap(self) {
        // check if this is the last ref
        let r = {
            let mut t = REG.lock();
            let ent = t[self.idx].as_mut().expect("mmio: stale");
            if ent.refs > 1 { ent.refs -= 1; return; }
            ent.clone()
        };

        // unmap full aligned range covering this region
        let start = VirtAddr::new(r.base_va & !((PAGE_SIZE as u64) - 1));
        let begin_off = (r.base_va & (PAGE_SIZE as u64 - 1)) as usize;
        let total = begin_off + r.len;
        let pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;

        for i in 0..pages {
            let va = VirtAddr::new(start.as_u64() + (i * PAGE_SIZE) as u64);
            let _ = virt::unmap4k(va);
        }
        proof::audit_unmap(start.as_u64(), (pages * PAGE_SIZE) as u64, CapTag::DMA | CapTag::KERNEL);

        let _ = reg_remove(self.idx);
    }

    // ——— typed volatile IO ———
    #[inline] pub fn read8 (&self, off: usize) ->  u8 { unsafe { ptr::read_volatile(self.ptr(off) as *const u8) } }
    #[inline] pub fn read16(&self, off: usize) -> u16 { unsafe { ptr::read_volatile(self.ptr(off) as *const u16) } }
    #[inline] pub fn read32(&self, off: usize) -> u32 { unsafe { ptr::read_volatile(self.ptr(off) as *const u32) } }
    #[inline] pub fn read64(&self, off: usize) -> u64 { unsafe { ptr::read_volatile(self.ptr(off) as *const u64) } }

    #[inline] pub fn write8 (&self, off: usize, v:  u8) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u8,  v) } }
    #[inline] pub fn write16(&self, off: usize, v: u16) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u16, v) } }
    #[inline] pub fn write32(&self, off: usize, v: u32) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u32, v) } }
    #[inline] pub fn write64(&self, off: usize, v: u64) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u64, v) } }

    /// Posted-write flush: read back a harmless register to ensure ordering.
    pub fn flush_posted(&self, readback_off: usize) {
        let _ = self.read32(readback_off);
        lfence();
    }

    #[inline] fn ptr(&self, off: usize) -> *mut u8 {
        assert!(off < self.len, "mmio: oob");
        (self.base.as_u64() as usize + off) as *mut u8
    }

    /// Retype cache attribute in-place (UC→WC, WT→WB, etc.) after PAT init.
    /// Rewrites PTE flags for the covered pages. Safe for live devices if
    /// ordering rules are observed by caller.
    pub unsafe fn retype(&self, kind: CacheKind) -> Result<(), ()> {
        let flags = vmflags_for(kind);
        // walk page range and update PTE flags in place
        let start = VirtAddr::new(self.base.as_u64() & !((PAGE_SIZE as u64) - 1));
        let begin_off = (self.base.as_u64() & (PAGE_SIZE as u64 - 1)) as usize;
        let total = begin_off + self.len;
        let pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;

        for i in 0..pages {
            let va = VirtAddr::new(start.as_u64() + (i * PAGE_SIZE) as u64);
            virt::protect4k(va, flags).map_err(|_| ())?;
        }
        Ok(())
    }

    // ——— MSI/MSI-X helpers ———
    /// Mask/unmask MSI-X entry in table mapped via this MMIO window.
    pub fn msix_mask_entry(&self, table_off: usize, entry: u16, mask: bool) {
        // MSI-X vector control: offset = table + entry*16 + 12; bit 0 = Mask
        let off = table_off + (entry as usize)*16 + 12;
        let mut v = self.read32(off);
        if mask { v |= 1 } else { v &= !1 };
        self.write32(off, v);
        sfence();
        self.flush_posted(off);
    }

    /// Program MSI/MSI-X address/data (doorbell) — typical for x86 APIC
    pub fn msix_program(&self, table_off: usize, entry: u16, addr: u64, data: u32) {
        let base = table_off + (entry as usize)*16;
        self.write32(base + 0, (addr & 0xFFFF_FFFF) as u32);
        self.write32(base + 4, (addr >> 32) as u32);
        self.write32(base + 8, data);
        sfence();
        self.flush_posted(base);
    }
}

/// Map a single 4K probe page; returns VA adjusted by original offset.
pub unsafe fn probe_map(pa: PhysAddr, kind: CacheKind) -> Result<VirtAddr, ()> {
    let flags = vmflags_for(kind);
    let base = map_mmio_pages(PhysAddr::new(pa.as_u64() & !((PAGE_SIZE as u64)-1)), 1, flags).map_err(|_| ())?;
    proof::audit_map(base.as_u64(), pa.as_u64() & !((PAGE_SIZE as u64)-1), PAGE_SIZE as u64, flags.bits(), CapTag::DMA | CapTag::KERNEL);
    Ok(VirtAddr::new(base.as_u64() + (pa.as_u64() & (PAGE_SIZE as u64 - 1))))
}

pub unsafe fn probe_unmap(adj_va: VirtAddr) {
    let va = VirtAddr::new(adj_va.as_u64() & !((PAGE_SIZE as u64)-1));
    let _ = virt::unmap4k(va);
    proof::audit_unmap(va.as_u64(), PAGE_SIZE as u64, CapTag::DMA | CapTag::KERNEL);
}

// —————————————————— internals ——————————————————


unsafe fn map_mmio_pages(pa_aligned: PhysAddr, pages: usize, flags: VmFlags) -> Result<VirtAddr, ()> {
    extern "Rust" { fn __nonos_alloc_mmio_va(pages: usize) -> u64; }
    let va_base = __nonos_alloc_mmio_va(pages);
    if va_base == 0 { return Err(()); }

    for i in 0..pages {
        let va = VirtAddr::new(va_base + (i * PAGE_SIZE) as u64);
        let pa = PhysAddr::new(pa_aligned.as_u64() + (i * PAGE_SIZE) as u64);
        virt::map4k_at(va, pa, flags).map_err(|_| ())?;
    }
    Ok(VirtAddr::new(va_base))
}

/// Convenience functions for MMIO register access
/// These provide a simpler interface for driver development

/// Read 16-bit value from MMIO address
#[inline]
pub unsafe fn mmio_r16(addr: usize) -> u16 {
    core::ptr::read_volatile(addr as *const u16)
}

/// Read 32-bit value from MMIO address
#[inline]
pub unsafe fn mmio_r32(addr: usize) -> u32 {
    core::ptr::read_volatile(addr as *const u32)
}

/// Read 64-bit value from MMIO address
#[inline]
pub unsafe fn mmio_r64(addr: usize) -> u64 {
    core::ptr::read_volatile(addr as *const u64)
}

/// Write 16-bit value to MMIO address
#[inline]
pub unsafe fn mmio_w16(addr: usize, value: u16) {
    core::ptr::write_volatile(addr as *mut u16, value);
}

/// Write 32-bit value to MMIO address
#[inline]
pub unsafe fn mmio_w32(addr: usize, value: u32) {
    core::ptr::write_volatile(addr as *mut u32, value);
}

/// Write 64-bit value to MMIO address
#[inline]
pub unsafe fn mmio_w64(addr: usize, value: u64) {
    core::ptr::write_volatile(addr as *mut u64, value);
}
