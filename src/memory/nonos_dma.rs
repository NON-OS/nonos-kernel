// DMA allocator and mapping helpers 

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::nonos_phys as phys;
use crate::memory::nonos_phys::AllocFlags;
use crate::memory::virt::{self, VmFlags};
use crate::memory::layout::PAGE_SIZE;

pub type PhysicalAddress = PhysAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDir {
    ToDevice,
    FromDevice,
    Bidirectional,
}

#[derive(Debug, Clone, Copy)]
pub struct DmaPage {
    pub virt: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
}

#[derive(Debug)]
pub struct DmaMapping {
    pub dma_addr: PhysAddr,
    pub len: usize,
    pub bounce: Option<DmaPage>,
    pub dir: DmaDir,
    orig_va: VirtAddr,
}

// VA carve-out windows for DMA
const DMA_VA_BASE_64: u64 = 0xFFFF_9800_0000_0000;
const DMA_VA_END_64:  u64 = 0xFFFF_9A00_0000_0000;

const DMA_VA_BASE_32: u64 = 0xFFFF_9A00_0000_0000;
const DMA_VA_END_32:  u64 = 0xFFFF_9B00_0000_0000;

static DMA_NEXT_64: AtomicU64 = AtomicU64::new(DMA_VA_BASE_64);
static DMA_NEXT_32: AtomicU64 = AtomicU64::new(DMA_VA_BASE_32);

#[inline]
fn dma_flags_coherent() -> VmFlags {
    // RW, non-executable, global, cache disabled and write-through for device coherency
    VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD | VmFlags::PWT
}

fn alloc_dma_va_64(pages: usize) -> Option<VirtAddr> {
    let bytes = (pages * PAGE_SIZE) as u64;
    let base = DMA_NEXT_64
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
            let next = cur.checked_add(bytes)?;
            if next > DMA_VA_END_64 { None } else { Some(next) }
        })
        .ok()?;
    Some(VirtAddr::new(base))
}

fn alloc_dma_va_32(pages: usize) -> Option<VirtAddr> {
    let bytes = (pages * PAGE_SIZE) as u64;
    let base = DMA_NEXT_32
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |cur| {
            let next = cur.checked_add(bytes)?;
            if next > DMA_VA_END_32 { None } else { Some(next) }
        })
        .ok()?;
    Some(VirtAddr::new(base))
}

/// Initialize DMA allocator (idempotent)
pub fn init_dma_allocator() -> Result<(), &'static str> {
    // Windows are static; nothing else required for now.
    Ok(())
}

/// Allocate one 4K DMA-coherent page anywhere (<64-bit)
pub fn alloc_dma_page() -> Option<DmaPage> {
    alloc_dma_pages_aligned(1, 1, false)
}

/// Free a DMA page previously allocated (unmap + free frames)
pub fn free_dma_page(p: DmaPage) {
    let pages = (p.size + PAGE_SIZE - 1) / PAGE_SIZE;
    let va_base = VirtAddr::new(p.virt.as_u64() & !((PAGE_SIZE as u64) - 1));
    for i in 0..pages {
        let va = VirtAddr::new(va_base.as_u64() + (i * PAGE_SIZE) as u64);
        let _ = virt::unmap4k(va);
    }
    // Physically contiguous region was allocated; free frames explicitly
    phys::free_contig(phys::Frame(p.phys_addr.as_u64()), pages);
}

/// Allocate n contiguous coherent pages, aligned to align_pages (power-of-two).
/// If must_32bit is true, ensure physical addressability under 4 GiB.
pub fn alloc_dma_pages_aligned(n_pages: usize, align_pages: usize, must_32bit: bool) -> Option<DmaPage> {
    assert!(align_pages.is_power_of_two());
    if n_pages == 0 { return None; }

    let frames = phys::alloc_contig(
        n_pages,
        align_pages,
        if must_32bit { AllocFlags::DMA32 } else { AllocFlags::empty() }
    )?;
    let base_phys = PhysAddr::new(frames.0);
    let va_base = if must_32bit { alloc_dma_va_32(n_pages)? } else { alloc_dma_va_64(n_pages)? };
    let flags = dma_flags_coherent();

    for i in 0..n_pages {
        let va = VirtAddr::new(va_base.as_u64() + (i * PAGE_SIZE) as u64);
        let pa = PhysAddr::new(base_phys.as_u64() + (i * PAGE_SIZE) as u64);
        if let Err(_e) = virt::map4k_at(va, pa, flags) {
            // rollback on failure
            for j in 0..i {
                let va_j = VirtAddr::new(va_base.as_u64() + (j * PAGE_SIZE) as u64);
                let _ = virt::unmap4k(va_j);
            }
            phys::free_contig(phys::Frame(base_phys.as_u64()), n_pages);
            return None;
        }
    }

    Some(DmaPage { virt: va_base, phys_addr: base_phys, size: n_pages * PAGE_SIZE })
}

/// Coherent allocation as expected by drivers/monster drivers
pub fn alloc_dma_coherent(size: usize) -> Result<(VirtAddr, PhysAddr), &'static str> {
    if size == 0 { return Err("invalid size"); }
    let n_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let page = alloc_dma_pages_aligned(n_pages, 1, false).ok_or("dma alloc failed")?;
    Ok((page.virt, page.phys_addr))
}

pub fn free_dma_coherent(virt_addr: VirtAddr, phys_addr: PhysAddr, size: usize) {
    if size == 0 { return; }
    let pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    let va_base = VirtAddr::new(virt_addr.as_u64() & !((PAGE_SIZE as u64) - 1));
    for i in 0..pages {
        let va = VirtAddr::new(va_base.as_u64() + (i * PAGE_SIZE) as u64);
        let _ = virt::unmap4k(va);
    }
    phys::free_contig(phys::Frame(phys_addr.as_u64() & !((PAGE_SIZE as u64) - 1)), pages);
}

/// Streaming map: If the buffer is contiguous+addressable, return direct DMA address;
/// otherwise allocate a bounce and copy as needed.
pub fn map_streaming(buf_va: VirtAddr, len: usize, dir: DmaDir, require_32bit: bool) -> Option<DmaMapping> {
    if len == 0 { return None; }

    // Probe contiguity across pages
    let (first_pa, _fl, _sz) = crate::memory::virt::translate(buf_va).ok()?;
    let first_off = (buf_va.as_u64() & (PAGE_SIZE as u64 - 1)) as usize;

    let mut checked = PAGE_SIZE - first_off.min(PAGE_SIZE);
    let mut cur_pa = first_pa;

    while checked < len {
        let va = VirtAddr::new((buf_va.as_u64() & !0xFFF) + (checked as u64));
        let (pa, _f, _s) = crate::memory::virt::translate(va).ok()?;
        let expected = PhysAddr::new(cur_pa.as_u64() + (PAGE_SIZE as u64));
        if pa != expected {
            break;
        }
        cur_pa = pa;
        checked += PAGE_SIZE;
    }

    let fully_contig = checked >= len;

    if fully_contig {
        let dma_start = PhysAddr::new(first_pa.as_u64() + first_off as u64);
        if !(require_32bit && dma_start.as_u64().saturating_add(len as u64) > (1u64 << 32)) {
            return Some(DmaMapping { dma_addr: dma_start, len, bounce: None, dir, orig_va: buf_va });
        }
    }

    // Bounce path
    let pages = ((len + first_off + PAGE_SIZE - 1) / PAGE_SIZE).max(1);
    let bounce = alloc_dma_pages_aligned(pages, 1, require_32bit)?;
    let dst = unsafe { core::slice::from_raw_parts_mut(bounce.virt.as_mut_ptr::<u8>().add(first_off), len) };
    let src = unsafe { core::slice::from_raw_parts(buf_va.as_ptr::<u8>(), len) };

    if matches!(dir, DmaDir::ToDevice | DmaDir::Bidirectional) {
        dst.copy_from_slice(src);
    }

    Some(DmaMapping {
        dma_addr: PhysAddr::new(bounce.phys_addr.as_u64() + first_off as u64),
        len,
        bounce: Some(bounce),
        dir,
        orig_va: buf_va,
    })
}

/// Unmap streaming mapping; copy back if required
pub fn unmap_streaming(map: DmaMapping) {
    if let Some(b) = map.bounce {
        if matches!(map.dir, DmaDir::FromDevice | DmaDir::Bidirectional) {
            let src = unsafe { core::slice::from_raw_parts(b.virt.as_ptr::<u8>(), b.size) };
            let off = (map.dma_addr.as_u64() - b.phys_addr.as_u64()) as usize;
            let len = map.len.min(b.size.saturating_sub(off));
            let dst = unsafe { core::slice::from_raw_parts_mut(map.orig_va.as_mut_ptr::<u8>(), len) };
            dst.copy_from_slice(&src[off..off + len]);
        }
        free_dma_page(b);
    }
}

/* ----------------------- Simple DMA Pools ----------------------- */
// Minimal fixed-size coherent pool to satisfy create_dma_pool() users

#[derive(Debug)]
struct DmaPool {
    block_size: usize,
    blocks: alloc::vec::Vec<DmaPage>,
    free: alloc::vec::Vec<usize>, // indices into blocks
}

impl DmaPool {
    fn new(block_size: usize, count: usize) -> Result<Self, &'static str> {
        if block_size == 0 || count == 0 { return Err("invalid pool params"); }
        let pages = (block_size + PAGE_SIZE - 1) / PAGE_SIZE;

        let mut blocks = alloc::vec::Vec::with_capacity(count);
        let mut free = alloc::vec::Vec::with_capacity(count);

        for i in 0..count {
            let page = alloc_dma_pages_aligned(pages, 1, false).ok_or("dma pool alloc failed")?;
            blocks.push(page);
            free.push(i);
        }

        Ok(Self { block_size, blocks, free })
    }
}

struct Pools {
    // Could grow into per-size class; for now single global registry by size.
    pools: alloc::vec::Vec<DmaPool>,
}

static POOLS: Once<Mutex<Pools>> = Once::new();

fn pools() -> &'static Mutex<Pools> {
    POOLS.call_once(|| Mutex::new(Pools { pools: alloc::vec::Vec::new() }))
}

/// Create a DMA pool with fixed block size
pub fn create_dma_pool(block_size: usize, count: usize) -> Result<(), &'static str> {
    let mut g = pools().lock();
    // Avoid duplicate by the same size; simplistic policy
    if g.pools.iter().any(|p| p.block_size == block_size) {
        return Ok(());
    }
    let pool = DmaPool::new(block_size, count)?;
    g.pools.push(pool);
    Ok(())
}
