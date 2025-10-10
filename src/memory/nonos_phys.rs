// Physical memory allocator — zones, NUMA-aware, atomic bitmap.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::{cmp, ptr};
use lazy_static::lazy_static;
use spin::Mutex;

use crate::memory::layout::{align_down, align_up, Region, RegionKind, PAGE_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubPolicy {
    OnFree,
    OnAlloc,
    Never,
}

bitflags::bitflags! {
    pub struct AllocFlags: u32 {
        const ZERO       = 1<<0;
        const DMA32      = 1<<1;
        const LOWMEM     = 1<<2;
        const EXACT      = 1<<3;
        const HUGE_ONLY  = 1<<4;
        const NODE0      = 1<<8;
        const NODE1      = 1<<9;
        const NODE2      = 1<<10;
        const NODE3      = 1<<11;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZoneKind {
    Dma32,
    Normal,
    High,
}

#[derive(Default, Clone, Copy, Debug)]
pub struct ZoneStats {
    pub frames_total: usize,
    pub frames_used: usize,
    pub frames_free: usize,
    pub high_watermark: usize,
}

pub trait AuditSink: Send + Sync {
    fn on_reserve(&self, paddr: u64, frames: usize);
    fn on_alloc(&self, paddr: u64, frames: usize, flags: AllocFlags);
    fn on_free(&self, paddr: u64, frames: usize);
}

struct Span {
    base: u64,
    frames: usize,
    words: &'static mut [AtomicU64],
    next_hint: AtomicUsize,
    stats: ZoneStats,
}

impl Span {
    #[inline]
    fn end(&self) -> u64 {
        self.base + (self.frames as u64) * (PAGE_SIZE as u64)
    }

    #[inline]
    fn idx_to_paddr(&self, idx: usize) -> u64 {
        self.base + (idx as u64) * (PAGE_SIZE as u64)
    }

    #[inline]
    fn paddr_to_idx(&self, addr: u64) -> usize {
        debug_assert!(addr >= self.base && addr < self.end());
        ((addr - self.base) as usize) / PAGE_SIZE
    }

    #[inline]
    fn words_len(&self) -> usize {
        self.words.len()
    }

    #[inline]
    fn bump_hint_after(&self, idx: usize) {
        let cur = self.next_hint.load(Ordering::Relaxed);
        if idx <= cur {
            self.next_hint.store(idx, Ordering::Relaxed);
        }
    }

    #[inline]
    fn test_bit(&self, idx: usize) -> bool {
        let (w, b) = (idx / 64, idx % 64);
        (self.words[w].load(Ordering::Relaxed) & (1u64 << b)) != 0
    }

    #[inline]
    fn claim_bit(&self, idx: usize) {
        let (w, b) = (idx / 64, idx % 64);
        let _ = self.words[w].fetch_or(1u64 << b, Ordering::AcqRel);
    }

    #[inline]
    fn clear_bit(&self, idx: usize) {
        let (w, b) = (idx / 64, idx % 64);
        let _ = self.words[w].fetch_and(!(1u64 << b), Ordering::AcqRel);
    }

    fn mark_used(&mut self, idx: usize) {
        if idx >= self.frames {
            return;
        }
        if !self.test_bit(idx) {
            self.claim_bit(idx);
            self.stats.frames_used += 1;
            self.stats.frames_free = self.stats.frames_total - self.stats.frames_used;
            self.stats.high_watermark = cmp::max(self.stats.high_watermark, self.stats.frames_used);
        }
    }

    fn find_and_claim_from_hint(&mut self) -> Option<usize> {
        let start = self.next_hint.load(Ordering::Relaxed);
        let start_word = start / 64;
        if let Some(i) = self.scan_range(start_word, self.words_len()) {
            self.next_hint.store(i.saturating_add(1), Ordering::Relaxed);
            return Some(i);
        }
        if let Some(i) = self.scan_range(0, start_word) {
            self.next_hint.store(i.saturating_add(1), Ordering::Relaxed);
            return Some(i);
        }
        None
    }

    fn scan_range(&self, w_begin: usize, w_end: usize) -> Option<usize> {
        let frames = self.frames;
        for w in w_begin..w_end {
            let raw = self.words[w].load(Ordering::Relaxed);
            let mut free_mask = !raw;
            let last_word = frames / 64;
            if w == last_word && (frames % 64) != 0 {
                let valid = (frames % 64) as u32;
                free_mask &= (1u64 << valid) - 1;
                if free_mask == 0 {
                    continue;
                }
            }
            if free_mask == 0 {
                continue;
            }
            let tz = free_mask.trailing_zeros() as usize;
            let idx = w * 64 + tz;
            let before = self.words[w].fetch_or(1u64 << tz, Ordering::AcqRel);
            if (before & (1u64 << tz)) == 0 {
                return Some(idx);
            }
        }
        None
    }

    fn find_contig(&self, n: usize, align_frames: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }
        let mut i = self.next_hint.load(Ordering::Relaxed);
        i = (i + (align_frames - 1)) & !(align_frames - 1);
        let total = self.frames;
        'outer: while i + n <= total {
            if self.test_bit(i) {
                i = (i + align_frames) & !(align_frames - 1);
                continue;
            }
            for j in 0..n {
                if self.test_bit(i + j) {
                    i = (i + j + 1 + (align_frames - 1)) & !(align_frames - 1);
                    continue 'outer;
                }
            }
            return Some(i);
        }
        None
    }

    fn after_alloc(&mut self, n: usize) {
        self.stats.frames_used += n;
        self.stats.frames_free = self.stats.frames_total - self.stats.frames_used;
        self.stats.high_watermark = cmp::max(self.stats.high_watermark, self.stats.frames_used);
    }

    fn after_free(&mut self, idx: usize, n: usize) {
        self.stats.frames_used = self.stats.frames_used.saturating_sub(n);
        self.stats.frames_free = self.stats.frames_total - self.stats.frames_used;
        self.next_hint.store(idx, Ordering::Relaxed);
    }
}

struct Zone {
    node_id: u8,
    kind: ZoneKind,
    span: Span,
}

impl Zone {
    fn name(&self) -> &'static str {
        match self.kind {
            ZoneKind::Dma32 => "DMA32",
            ZoneKind::Normal => "NORMAL",
            ZoneKind::High => "HIGHMEM",
        }
    }
}

struct PhysState {
    scrub: ScrubPolicy,
    audit: Option<&'static dyn AuditSink>,
    zones: heapless::Vec<Zone, 8>,
}

lazy_static! {
    static ref PHYS: Mutex<Option<PhysState>> = Mutex::new(None);
}

impl PhysState {
    pub unsafe fn init_from_regions<F>(
        regions: &'static [Region],
        node_id: u8,
        scrub: ScrubPolicy,
        mut carve: F,
        audit: Option<&'static dyn AuditSink>,
    ) where
        F: FnMut(usize) -> &'static mut [AtomicU64],
    {
        let mut st = PhysState { scrub, audit, zones: heapless::Vec::new() };

        for target in [ZoneKind::Dma32, ZoneKind::Normal, ZoneKind::High] {
            let mut lo = u64::MAX;
            let mut hi = 0u64;

            for r in regions {
                if !matches!(r.kind, RegionKind::Usable) {
                    continue;
                }
                let start = align_up(r.start, PAGE_SIZE as u64);
                let end = align_down(r.end, PAGE_SIZE as u64);
                if end <= start {
                    continue;
                }
                match target {
                    ZoneKind::Dma32 if end <= (1u64 << 32) => {
                        lo = lo.min(start);
                        hi = hi.max(end);
                    }
                    ZoneKind::Normal if start < (1u64 << 32) && end > (1u64 << 32) => {
                        lo = lo.min(1u64 << 32);
                        hi = hi.max(end);
                    }
                    ZoneKind::High if start >= (1u64 << 32) => {
                        lo = lo.min(start);
                        hi = hi.max(end);
                    }
                    _ => {}
                }
            }

            if lo >= hi || lo == u64::MAX {
                continue;
            }

            let frames = ((hi - lo) / PAGE_SIZE as u64) as usize;
            if frames == 0 {
                continue;
            }
            let words = (frames + 63) / 64;
            let map = carve(words);

            let mut stats = ZoneStats::default();
            stats.frames_total = frames;
            stats.frames_free = frames;

            let span = Span {
                base: lo,
                frames,
                words: map,
                next_hint: AtomicUsize::new(0),
                stats,
            };
            let _ = st.zones.push(Zone { node_id, kind: target, span });
        }

        *PHYS.lock() = Some(st);
    }

    pub fn reserve_range(paddr: u64, len: u64) {
        let mut g = PHYS.lock();
        let st = g.as_mut().expect("phys not initialized");
        for z in st.zones.iter_mut() {
            if paddr >= z.span.end() || paddr + len <= z.span.base {
                continue;
            }
            let begin = cmp::max(paddr, z.span.base);
            let end = cmp::min(paddr + len, z.span.end());
            let s = z.span.paddr_to_idx(align_down(begin, PAGE_SIZE as u64));
            let e = z.span.paddr_to_idx(align_up(end, PAGE_SIZE as u64));
            for i in s..e {
                z.span.mark_used(i);
            }
            z.span.bump_hint_after(s);
            if let Some(a) = st.audit {
                a.on_reserve(align_down(begin, PAGE_SIZE as u64), e - s);
            }
        }
    }

    pub fn alloc(flags: AllocFlags) -> Option<Frame> {
        Self::alloc_contig(1, 1, flags)
    }

    pub fn alloc_contig(n: usize, align_frames: usize, flags: AllocFlags) -> Option<Frame> {
        assert!(align_frames.is_power_of_two());
        let mut g = PHYS.lock();
        let st = g.as_mut()?;

        let mut candidates: heapless::Vec<usize, 8> = heapless::Vec::new();
        for (idx, z) in st.zones.iter().enumerate() {
            match z.kind {
                ZoneKind::Dma32 if flags.contains(AllocFlags::DMA32) => {
                    let _ = candidates.push(idx);
                }
                ZoneKind::Dma32 if flags.contains(AllocFlags::LOWMEM) => {
                    let _ = candidates.push(idx);
                }
                ZoneKind::Normal if !flags.contains(AllocFlags::DMA32) => {
                    let _ = candidates.push(idx);
                }
                ZoneKind::High if !(flags.contains(AllocFlags::DMA32) || flags.contains(AllocFlags::LOWMEM)) => {
                    let _ = candidates.push(idx);
                }
                _ => {}
            }
        }
        if candidates.is_empty() {
            for (idx, _) in st.zones.iter().enumerate() {
                let _ = candidates.push(idx);
            }
        }

        for &zi in candidates.iter() {
            let z = &mut st.zones[zi];
            if let Some(start) = z.span.find_contig(n, align_frames) {
                for i in 0..n {
                    z.span.claim_bit(start + i);
                }
                z.span.after_alloc(n);
                let addr = z.span.idx_to_paddr(start);
                if st.scrub == ScrubPolicy::OnAlloc || flags.contains(AllocFlags::ZERO) {
                    unsafe { ptr::write_bytes(addr as *mut u8, 0, n * PAGE_SIZE) }
                }
                if let Some(a) = st.audit {
                    a.on_alloc(addr, n, flags);
                }
                return Some(Frame(addr));
            }
        }

        if flags.contains(AllocFlags::EXACT) {
            return None;
        }
        None
    }

    pub fn alloc_at(paddr: u64, flags: AllocFlags) -> bool {
        let mut g = PHYS.lock();
        let st = g.as_mut().expect("phys not initialized");
        for z in st.zones.iter_mut() {
            if paddr < z.span.base || paddr >= z.span.end() {
                continue;
            }
            let idx = z.span.paddr_to_idx(paddr);
            if z.span.test_bit(idx) {
                return false;
            }
            z.span.claim_bit(idx);
            z.span.after_alloc(1);
            if st.scrub == ScrubPolicy::OnAlloc || flags.contains(AllocFlags::ZERO) {
                unsafe { ptr::write_bytes(paddr as *mut u8, 0, PAGE_SIZE) }
            }
            if let Some(a) = st.audit {
                a.on_alloc(paddr, 1, flags);
            }
            return true;
        }
        false
    }

    pub fn free(f: Frame) {
        Self::free_contig(f, 1);
    }

    pub fn free_contig(base: Frame, n: usize) {
        let mut g = PHYS.lock();
        let st = g.as_mut().expect("phys not initialized");
        for z in st.zones.iter_mut() {
            if base.0 < z.span.base || base.0 >= z.span.end() {
                continue;
            }
            let idx0 = z.span.paddr_to_idx(base.0);
            if st.scrub == ScrubPolicy::OnFree {
                unsafe { ptr::write_bytes(base.0 as *mut u8, 0, n * PAGE_SIZE) }
            }
            for i in 0..n {
                z.span.clear_bit(idx0 + i);
            }
            z.span.after_free(idx0, n);
            if let Some(a) = st.audit {
                a.on_free(base.0, n);
            }
            return;
        }
        debug_assert!(false, "free_contig: frame not in any zone");
    }

    pub fn zone_stats() -> heapless::Vec<(ZoneKind, ZoneStats), 8> {
        let g = PHYS.lock();
        let st = g.as_ref().expect("phys not initialized");
        let mut out = heapless::Vec::new();
        for z in st.zones.iter() {
            let _ = out.push((z.kind, z.span.stats));
        }
        out
    }

    #[cfg(feature = "nonos-hash-sha3")]
    pub fn bitmap_hash() -> [u8; 32] {
        use crate::crypto::sha3::Sha3_256;
        let g = PHYS.lock();
        let st = g.as_ref().expect("phys not initialized");
        let mut h = Sha3_256::new();
        for z in st.zones.iter() {
            for w in z.span.words.iter() {
                h.update(&w.load(Ordering::Relaxed).to_le_bytes());
            }
        }
        h.finalize()
    }

    #[cfg(not(feature = "nonos-hash-sha3"))]
    pub fn bitmap_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        let g = PHYS.lock();
        let st = g.as_ref().expect("phys not initialized");
        let mut counter = 0u8;
        for z in st.zones.iter() {
            for w in z.span.words.iter() {
                let word = w.load(Ordering::Relaxed);
                hash[counter as usize % 32] ^= (word as u8);
                counter = counter.wrapping_add(1);
            }
        }
        hash
    }

    pub fn set_audit_sink(sink: Option<&'static dyn AuditSink>) {
        let mut g = PHYS.lock();
        if let Some(st) = g.as_mut() {
            st.audit = sink;
        }
    }

    pub fn is_frame_available(frame: Frame) -> bool {
        let g = PHYS.lock();
        if let Some(st) = g.as_ref() {
            for zone in &st.zones {
                if frame.0 >= zone.span.base && frame.0 < zone.span.end() {
                    let frame_idx = ((frame.0 - zone.span.base) / (PAGE_SIZE as u64)) as usize;
                    let word_idx = frame_idx / 64;
                    let bit_idx = frame_idx % 64;
                    if let Some(word) = zone.span.words.get(word_idx) {
                        let used = word.load(Ordering::Relaxed) & (1 << bit_idx) != 0;
                        return !used;
                    }
                }
            }
        }
        false
    }

    pub fn mark_frame_used(frame: Frame) {
        let g = PHYS.lock();
        if let Some(st) = g.as_ref() {
            for zone in &st.zones {
                if frame.0 >= zone.span.base && frame.0 < zone.span.end() {
                    let frame_idx = ((frame.0 - zone.span.base) / (PAGE_SIZE as u64)) as usize;
                    let word_idx = frame_idx / 64;
                    let bit_idx = frame_idx % 64;
                    if let Some(word) = zone.span.words.get(word_idx) {
                        word.fetch_or(1 << bit_idx, Ordering::Relaxed);
                    }
                    break;
                }
            }
        }
    }
}

pub fn init_from_regions<F>(
    regions: &'static [Region],
    node_id: u8,
    scrub: ScrubPolicy,
    carve: F,
    audit: Option<&'static dyn AuditSink>,
) where
    F: FnMut(usize) -> &'static mut [AtomicU64],
{
    unsafe { PhysState::init_from_regions(regions, node_id, scrub, carve, audit) }
}

pub fn reserve_range(paddr: u64, len: u64) {
    PhysState::reserve_range(paddr, len)
}
pub fn alloc(flags: AllocFlags) -> Option<Frame> {
    PhysState::alloc(flags)
}
pub fn alloc_contig(n: usize, align_frames: usize, flags: AllocFlags) -> Option<Frame> {
    PhysState::alloc_contig(n, align_frames, flags)
}
pub fn alloc_frames(count: usize) -> Option<u64> {
    alloc_contig(count, 1, AllocFlags::empty()).map(|f| f.0)
}
pub fn alloc_at(paddr: u64, flags: AllocFlags) -> bool {
    PhysState::alloc_at(paddr, flags)
}
pub fn free(f: Frame) {
    PhysState::free(f)
}
pub fn free_contig(base: Frame, n: usize) {
    PhysState::free_contig(base, n)
}
pub fn zone_stats() -> heapless::Vec<(ZoneKind, ZoneStats), 8> {
    PhysState::zone_stats()
}
pub fn bitmap_hash() -> [u8; 32] {
    PhysState::bitmap_hash()
}

pub fn is_frame_available(addr: x86_64::PhysAddr) -> bool {
    let frame = Frame(addr.as_u64());
    PhysState::is_frame_available(frame)
}

pub fn mark_frame_used(addr: x86_64::PhysAddr) {
    let frame = Frame(addr.as_u64());
    PhysState::mark_frame_used(frame);
}

pub fn init_from_bootinfo(_boot_info: &'static bootloader_api::BootInfo) {
    use crate::memory::layout::{Region, RegionKind};

    // Minimal usable slice; production path should parse boot info map.
    static REGIONS: [Region; 1] = [Region {
        start: 0x0010_0000,
        end: 0x0010_0000 + 64 * 1024 * 1024,
        kind: RegionKind::Usable,
    }];

    fn carve(words_needed: usize) -> &'static mut [AtomicU64] {
        use core::slice;
        static mut BITMAP_STORAGE: [AtomicU64; 4096] = {
            const Z: AtomicU64 = AtomicU64::new(0);
            [Z; 4096]
        };
        assert!(words_needed <= 4096, "bitmap carve exhausted");
        unsafe { slice::from_raw_parts_mut(BITMAP_STORAGE.as_mut_ptr(), words_needed) }
    }

    init_from_regions(&REGIONS, 0, ScrubPolicy::OnFree, carve, None);
}
