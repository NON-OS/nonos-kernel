// Device MMIO mapping (PAT-aware), typed volatile access, MSI/MSI-X helpers.

#![allow(dead_code)]

use core::{ptr, sync::atomic::{AtomicU64, Ordering}, marker::PhantomData};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};
use crate::memory::virt::{self, VmFlags};

#[inline(always)] pub fn lfence() { unsafe { core::arch::asm!("lfence", options(nomem, nostack, preserves_flags)) } }
#[inline(always)] pub fn sfence() { unsafe { core::arch::asm!("sfence", options(nomem, nostack, preserves_flags)) } }
#[inline(always)] pub fn mfence() { unsafe { core::arch::asm!("mfence", options(nomem, nostack, preserves_flags)) } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheKind { UC, UcMinus, WC, WT, WB }

pub type CacheAttr = CacheKind;

pub fn pat_flags_for(kind: CacheKind) -> Option<VmFlags> {
    match kind {
        CacheKind::UC       => Some(VmFlags::PCD),
        CacheKind::UcMinus  => Some(VmFlags::PCD | VmFlags::PWT),
        CacheKind::WT       => Some(VmFlags::PWT),
        CacheKind::WB       => Some(VmFlags::empty()),
        CacheKind::WC       => None, // require PAT programming; fallback applied below
    }
}

#[derive(Clone, Copy)]
struct Region {
    base_va: u64,
    base_pa: u64,
    len:     usize,
    flags:   VmFlags,
    refs:    u32,
    label:   [u8; 16],
}

const MAX_MMIO: usize = 128;
static REG: Mutex<[Option<Region>; MAX_MMIO]> = Mutex::new([None; MAX_MMIO]);

fn reg_insert(r: Region) -> Result<usize, ()> {
    let mut t = REG.lock();
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

fn reg_remove(idx: usize) -> Region {
    let mut t = REG.lock();
    t[idx].take().expect("mmio: missing reg")
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
    let base = VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL;
    match pat_flags_for(kind).or_else(|| pat_flags_for(CacheKind::UC)) {
        Some(extra) => base | extra,
        None => base | VmFlags::PCD,
    }
}

// Simple VA allocator for MMIO window: [MMIO_VA_BASE, MMIO_VA_END)
const MMIO_VA_BASE: u64 = 0xFFFF_9000_0000_0000;
const MMIO_VA_END:  u64 = 0xFFFF_9800_0000_0000;
static MMIO_NEXT: AtomicU64 = AtomicU64::new(MMIO_VA_BASE);

fn alloc_mmio_va_pages(pages: usize) -> Result<VirtAddr, ()> {
    let bytes = (pages * PAGE_SIZE) as u64;
    let base = MMIO_NEXT.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
        let next = cur.checked_add(bytes)?;
        if next > MMIO_VA_END { None } else { Some(next) }
    }).map_err(|_| ())?;
    Ok(VirtAddr::new(base))
}

pub struct Mmio {
    base: VirtAddr,
    len:  usize,
    idx:  usize,
    _nosend: PhantomData<*mut ()>,
}

impl Mmio {
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
            label: [0; 16],
        })?;
        reg_set_label(idx, label);

        Ok(Self { base: VirtAddr::new(base.as_u64() + off as u64), len, idx, _nosend: PhantomData })
    }

    pub fn clone_ref(&self) -> Self {
        reg_addref(self.idx);
        Self { base: self.base, len: self.len, idx: self.idx, _nosend: PhantomData }
    }

    pub unsafe fn iounmap(self) {
        let r = {
            let mut t = REG.lock();
            let ent = t[self.idx].as_mut().expect("mmio: stale");
            if ent.refs > 1 { ent.refs -= 1; return; }
            *ent
        };

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

    #[inline] pub fn read8 (&self, off: usize) ->  u8 { unsafe { ptr::read_volatile(self.ptr(off) as *const u8) } }
    #[inline] pub fn read16(&self, off: usize) -> u16 { unsafe { ptr::read_volatile(self.ptr(off) as *const u16) } }
    #[inline] pub fn read32(&self, off: usize) -> u32 { unsafe { ptr::read_volatile(self.ptr(off) as *const u32) } }
    #[inline] pub fn read64(&self, off: usize) -> u64 { unsafe { ptr::read_volatile(self.ptr(off) as *const u64) } }

    #[inline] pub fn write8 (&self, off: usize, v:  u8) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u8,  v) } }
    #[inline] pub fn write16(&self, off: usize, v: u16) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u16, v) } }
    #[inline] pub fn write32(&self, off: usize, v: u32) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u32, v) } }
    #[inline] pub fn write64(&self, off: usize, v: u64) { unsafe { ptr::write_volatile(self.ptr(off) as *mut u64, v) } }

    pub fn flush_posted(&self, readback_off: usize) {
        let _ = self.read32(readback_off);
        lfence();
    }

    #[inline] fn ptr(&self, off: usize) -> *mut u8 {
        assert!(off < self.len, "mmio: oob");
        (self.base.as_u64() as usize + off) as *mut u8
    }

    pub unsafe fn retype(&self, kind: CacheKind) -> Result<(), ()> {
        let flags = vmflags_for(kind);
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

    pub fn msix_mask_entry(&self, table_off: usize, entry: u16, mask: bool) {
        let off = table_off + (entry as usize) * 16 + 12;
        let mut v = self.read32(off);
        if mask { v |= 1 } else { v &= !1 }
        self.write32(off, v);
        sfence();
        self.flush_posted(off);
    }

    pub fn msix_program(&self, table_off: usize, entry: u16, addr: u64, data: u32) {
        let base = table_off + (entry as usize) * 16;
        self.write32(base + 0, (addr & 0xFFFF_FFFF) as u32);
        self.write32(base + 4, (addr >> 32) as u32);
        self.write32(base + 8, data);
        sfence();
        self.flush_posted(base);
    }
}

pub unsafe fn probe_map(pa: PhysAddr, kind: CacheKind) -> Result<VirtAddr, ()> {
    let flags = vmflags_for(kind);
    let base = map_mmio_pages(PhysAddr::new(pa.as_u64() & !((PAGE_SIZE as u64) - 1)), 1, flags).map_err(|_| ())?;
    proof::audit_map(base.as_u64(), pa.as_u64() & !((PAGE_SIZE as u64) - 1), PAGE_SIZE as u64, flags.bits(), CapTag::DMA | CapTag::KERNEL);
    Ok(VirtAddr::new(base.as_u64() + (pa.as_u64() & (PAGE_SIZE as u64 - 1))))
}

pub unsafe fn probe_unmap(adj_va: VirtAddr) {
    let va = VirtAddr::new(adj_va.as_u64() & !((PAGE_SIZE as u64) - 1));
    let _ = virt::unmap4k(va);
    proof::audit_unmap(va.as_u64(), PAGE_SIZE as u64, CapTag::DMA | CapTag::KERNEL);
}

unsafe fn map_mmio_pages(pa_aligned: PhysAddr, pages: usize, flags: VmFlags) -> Result<VirtAddr, ()> {
    let base = alloc_mmio_va_pages(pages)?;
    for i in 0..pages {
        let va = VirtAddr::new(base.as_u64() + (i * PAGE_SIZE) as u64);
        let pa = PhysAddr::new(pa_aligned.as_u64() + (i * PAGE_SIZE) as u64);
        virt::map4k_at(va, pa, flags).map_err(|_| ())?;
    }
    Ok(base)
}

#[inline] pub unsafe fn mmio_r16(addr: usize) -> u16 { core::ptr::read_volatile(addr as *const u16) }
#[inline] pub unsafe fn mmio_r32(addr: usize) -> u32 { core::ptr::read_volatile(addr as *const u32) }
#[inline] pub unsafe fn mmio_r64(addr: usize) -> u64 { core::ptr::read_volatile(addr as *const u64) }
#[inline] pub unsafe fn mmio_w16(addr: usize, value: u16) { core::ptr::write_volatile(addr as *mut u16, value) }
#[inline] pub unsafe fn mmio_w32(addr: usize, value: u32) { core::ptr::write_volatile(addr as *mut u32, value) }
#[inline] pub unsafe fn mmio_w64(addr: usize, value: u64) { core::ptr::write_volatile(addr as *mut u64, value) }
