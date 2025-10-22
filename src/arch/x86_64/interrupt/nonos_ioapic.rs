//! NØNOS I/O APIC Driver 

#![allow(dead_code)]
#![allow(unused)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use lazy_static::lazy_static;

use crate::memory::virt::{self, VmFlags};
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};

/// IOAPIC MMIO Registers
const IOREGSEL: u64 = 0x00; // selector (u32)
const IOWIN:    u64 = 0x10; // data     (u32)
const IOAPICID:  u32 = 0x00;
const IOAPICVER: u32 = 0x01;
const IOREDTBL0: u32 = 0x10; // two u32 per entry: low (even), high (odd)

/// Redirection Table Entry (RTE) for I/O APIC
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rte {
    pub vector: u8,
    pub delivery: u8, // 0=fixed, 4=NMI
    pub logical: bool,
    pub active_low: bool,
    pub level_trigger: bool,
    pub masked: bool,
    pub dest_apic_id: u32,
}

impl Rte {
    /// Create a fixed (masked) RTE for a given vector and APIC ID.
    pub const fn fixed(vector: u8, dest_apic_id: u32) -> Self {
        Self {
            vector, delivery: 0, logical: false,
            active_low: false, level_trigger: false, masked: true,
            dest_apic_id,
        }
    }
    /// Convert RTE to two u32s (low, high) for MMIO programming.
    pub fn to_u32s(self) -> (u32, u32) {
        let mut low = self.vector as u32;
        low |= (self.delivery as u32) << 8;
        if self.logical { low |= 1 << 11; }
        if self.active_low { low |= 1 << 13; }
        if self.level_trigger { low |= 1 << 15; }
        if self.masked { low |= 1 << 16; }
        let high = (self.dest_apic_id & 0xFF) << 24;
        (low, high)
    }
    /// Parse RTE from MMIO format.
    pub fn from_u32s(low: u32, high: u32) -> Self {
        Self {
            vector: (low & 0xFF) as u8,
            delivery: ((low >> 8) & 0x7) as u8,
            logical: (low & (1<<11)) != 0,
            active_low: (low & (1<<13)) != 0,
            level_trigger: (low & (1<<15)) != 0,
            masked: (low & (1<<16)) != 0,
            dest_apic_id: (high >> 24) & 0xFF,
        }
    }
}

/// MADT I/O APIC descriptor (from ACPI)
#[derive(Clone, Copy, Debug)]
pub struct MadtIoApic { pub phys_base: u64, pub gsi_base: u32 }

/// MADT ISO (Interrupt Source Override) descriptor
#[derive(Clone, Debug, Copy)]
pub struct MadtIso    { pub bus_irq: u8, pub gsi: u32, pub flags: IsoFlags }

/// MADT NMI descriptor
#[derive(Clone, Debug, Copy)]
pub struct MadtNmi    { pub cpu: u32, pub lint: u8, pub flags: IsoFlags }

bitflags::bitflags! {
    #[derive(Clone, Debug, Copy)]
    pub struct IsoFlags: u16 {
        const POLARITY_ACTIVE_HIGH = 0b00;
        const POLARITY_ACTIVE_LOW  = 0b10;
        const TRIGGER_EDGE         = 0b00_00_01_00;
        const TRIGGER_LEVEL        = 0b00_00_10_00;
    }
}

/// Registered IOAPIC chip state
#[derive(Clone, Copy)]
struct IoApicChip {
    gsi_base: u32,
    redirs:   u32,
    mmio:     VirtAddr,
}

const MAX_IOAPIC: usize = 8;
static IOAPICS: Mutex<[Option<IoApicChip>; MAX_IOAPIC]> = Mutex::new([None; MAX_IOAPIC]);
static COUNT: AtomicUsize = AtomicUsize::new(0);

struct VecIso {
    iso:  smallvec::SmallVec<[MadtIso; 16]>,
    nmis: smallvec::SmallVec<[MadtNmi; 8]>,
}

lazy_static! {
    static ref ISO: Mutex<VecIso> = Mutex::new(VecIso {
        iso: smallvec::SmallVec::new(),
        nmis: smallvec::SmallVec::new()
    });
}

/// Vector allocator (0x30..0x7E, skipping reserved and spurious)
static VEC_ALLOC: Mutex<VecAlloc> = Mutex::new(VecAlloc { next: 0x30, reserved: [false; 256] });
struct VecAlloc { next: u8, reserved: [bool; 256] }

impl VecAlloc {
    fn reserve(&mut self, v: u8) { self.reserved[v as usize] = true; }
    fn alloc(&mut self) -> Option<u8> {
        for _ in 0..200 {
            let v = self.next;
            self.next = if self.next >= 0x7E { 0x30 } else { self.next + 1 };
            if v >= 0x30 && v <= 0x7E && !self.reserved[v as usize] && v != 0xFF {
                self.reserved[v as usize] = true;
                return Some(v);
            }
        }
        None
    }
    fn free(&mut self, v: u8) { self.reserved[v as usize] = false; }
}

lazy_static! {
    /// Devices that switched to MSI/MSI-X (we won't route their GSIs)
    static ref MSI_CLAIMED_GSI: Mutex<bitvec::vec::BitVec> = Mutex::new(bitvec::vec::BitVec::repeat(false, 1024));
}

/// Map and register IOAPICs (MMIO UC). Provide MADT IOAPIC list first.
/// # Safety
/// Call in early boot with IRQs disabled.
pub unsafe fn init(ioapics: &[MadtIoApic], iso: &[MadtIso], nmis: &[MadtNmi]) -> Result<(), &'static str> {
    {
        let mut v = ISO.lock();
        v.iso.extend_from_slice(iso);
        v.nmis.extend_from_slice(nmis);
    }
    let mut t = IOAPICS.lock();
    let mut n = 0usize;
    for d in ioapics.iter().take(MAX_IOAPIC) {
        let va = map_mmio(PhysAddr::new(d.phys_base))?;
        let ver = reg_read(va, IOAPICVER);
        let maxredir = ((ver >> 16) & 0xFF) + 1;
        t[n] = Some(IoApicChip { gsi_base: d.gsi_base, redirs: maxredir, mmio: va });
        n += 1;
        proof::audit_map(va.as_u64(), d.phys_base, PAGE_SIZE as u64,
            (VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).bits(), CapTag::KERNEL);
        if let Some(logger) = crate::log::logger::try_get_logger() {
            if let Some(log_mgr) = logger.lock().as_mut() {
                log_mgr.log(crate::log::nonos_logger::Severity::Info, &format!(
                    "[IOAPIC] mmio=0x{:x} gsi_base={} redirs={}", d.phys_base, d.gsi_base, maxredir
                ));
            }
        }
    }
    COUNT.store(n, Ordering::Relaxed);
    {
        let mut va = VEC_ALLOC.lock();
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_TIMER);
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_THERMAL);
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_ERROR);
    }
    Ok(())
}

/// Count of IOAPICs registered.
pub fn count() -> usize { COUNT.load(Ordering::Relaxed) }

/// Claim a GSI for MSI/MSI-X path (we won't also program IOAPIC for this GSI)
pub fn claim_gsi_for_msi(gsi: u32) {
    let mut g = MSI_CLAIMED_GSI.lock();
    if (gsi as usize) < g.len() { g.set(gsi as usize, true); }
}

/// Allocate a vector for a given GSI, deriving flags from ISO table.
pub fn alloc_route(gsi: u32, dest_apic_id: u32) -> Result<(u8, Rte), &'static str> {
    ensure_not_msi(gsi)?;
    let mut va = VEC_ALLOC.lock();
    let vector = va.alloc().ok_or("Vector allocation failed")?;
    let mut rte = Rte::fixed(vector, dest_apic_id);
    if let Some(f) = iso_flags_for(gsi) {
        if f.contains(IsoFlags::TRIGGER_LEVEL) { rte.level_trigger = true; }
        if f.contains(IsoFlags::POLARITY_ACTIVE_LOW) { rte.active_low = true; }
    }
    rte.masked = true;
    Ok((vector, rte))
}

/// Program a route (write RTE to IOAPIC). Safe RMW sequence.
pub fn program_route(gsi: u32, rte: Rte) -> Result<(), &'static str> {
    let (chip, idx) = locate(gsi).ok_or("GSI not found")?;
    let (low, high) = rte.to_u32s();
    unsafe { redtbl_write(chip.mmio, idx, low, high); }
    proof::audit_phys_alloc(((gsi as u64)<<32) | rte.vector as u64,
        ((rte.dest_apic_id as u64)<<32) | rte_flags_bits(rte) as u64, CapTag::KERNEL);
    Ok(())
}

/// Mask or unmask a GSI. For level-triggered, ensure handler EOI'd LAPIC before unmasking.
pub fn mask(gsi: u32, masked: bool) -> Result<(), &'static str> {
    let (chip, idx) = locate(gsi).ok_or("GSI not found")?;
    unsafe {
        let (mut low, high) = redtbl_read(chip.mmio, idx);
        if masked { low |= 1<<16 } else { low &= !(1<<16) }
        redtbl_write(chip.mmio, idx, low, high);
    }
    Ok(())
}

/// Retarget destination APIC ID (for CPU affinity changes).
pub fn retarget(gsi: u32, dest_apic_id: u32) -> Result<(), &'static str> {
    let (chip, idx) = locate(gsi).ok_or("GSI not found")?;
    unsafe {
        let (low, mut high) = redtbl_read(chip.mmio, idx);
        high &= !(0xFF << 24);
        high |= (dest_apic_id & 0xFF) << 24;
        redtbl_write(chip.mmio, idx, low, high);
    }
    Ok(())
}

/// Free a vector previously allocated by alloc_route.
pub fn free_vector(vec: u8) {
    VEC_ALLOC.lock().free(vec);
}

/// Query current RTE for a GSI.
pub fn query(gsi: u32) -> Option<Rte> {
    let (chip, idx) = locate(gsi)?;
    let (low, high) = unsafe { redtbl_read(chip.mmio, idx) };
    Some(Rte::from_u32s(low, high))
}

/// Snapshot all RTEs (for suspend/debug). Returns (gsi, rte) pairs.
pub fn snapshot() -> Vec<(u32, Rte)> {
    let mut out = Vec::new();
    let t = IOAPICS.lock();
    for chip in t.iter().flatten() {
        for i in 0..chip.redirs {
            let (low, high) = unsafe { redtbl_read(chip.mmio, i) };
            out.push((chip.gsi_base + i, Rte::from_u32s(low, high)));
        }
    }
    out
}

/// Restore a snapshot (all masked).
pub fn restore(snap: &[(u32, Rte)]) {
    for (gsi, rte) in snap {
        let _ = program_route(*gsi, Rte { masked: true, ..*rte });
    }
}

// Internal helpers

fn ensure_not_msi(gsi: u32) -> Result<(), &'static str> {
    let g = MSI_CLAIMED_GSI.lock();
    if (gsi as usize) < g.len() && g[gsi as usize] {
        return Err("GSI is claimed for MSI");
    }
    Ok(())
}

fn iso_flags_for(gsi: u32) -> Option<IsoFlags> {
    let v = ISO.lock();
    for e in v.iso.iter() {
        if e.gsi == gsi { return Some(e.flags); }
    }
    None
}

fn locate(gsi: u32) -> Option<(IoApicChip, u32)> {
    let t = IOAPICS.lock();
    for chip in t.iter().flatten() {
        let start = chip.gsi_base;
        let end = chip.gsi_base + chip.redirs;
        if gsi >= start && gsi < end {
            return Some((*chip, gsi - start));
        }
    }
    None
}

unsafe fn map_mmio(pa: PhysAddr) -> Result<VirtAddr, &'static str> {
    extern "Rust" { fn __nonos_alloc_mmio_va(pages: usize) -> u64; }
    let va = VirtAddr::new(__nonos_alloc_mmio_va(1));
    virt::map4k_at(va, pa, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD)
        .map_err(|_| "MMIO mapping failed")?;
    Ok(va)
}

#[inline(always)]
fn reg_write(base: VirtAddr, index: u32, val: u32) {
    unsafe {
        let sel = (base.as_u64() + IOREGSEL) as *mut u32;
        let win = (base.as_u64() + IOWIN)    as *mut u32;
        core::ptr::write_volatile(sel, index);
        core::ptr::write_volatile(win, val);
    }
}
#[inline(always)]
fn reg_read(base: VirtAddr, index: u32) -> u32 {
    unsafe {
        let sel = (base.as_u64() + IOREGSEL) as *mut u32;
        let win = (base.as_u64() + IOWIN)    as *const u32;
        core::ptr::write_volatile(sel, index);
        core::ptr::read_volatile(win)
    }
}
unsafe fn redtbl_write(base: VirtAddr, i: u32, low: u32, high: u32) {
    // Intel SDM: write high then low
    reg_write(base, IOREDTBL0 + (i * 2) + 1, high);
    reg_write(base, IOREDTBL0 + (i * 2) + 0, low);
}
unsafe fn redtbl_read(base: VirtAddr, i: u32) -> (u32, u32) {
    let high = reg_read(base, IOREDTBL0 + (i * 2) + 1);
    let low  = reg_read(base, IOREDTBL0 + (i * 2) + 0);
    (low, high)
}
/// Pack RTE flags for audit event
fn rte_flags_bits(r: Rte) -> u32 {
    let mut f = 0u32;
    if r.logical { f |= 1<<0; }
    if r.active_low { f |= 1<<1; }
    if r.level_trigger { f |= 1<<2; }
    if r.masked { f |= 1<<3; }
    f | ((r.delivery as u32) << 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rte_pack_unpack() {
        let orig = Rte::fixed(42, 2);
        let (low, high) = orig.to_u32s();
        let unpacked = Rte::from_u32s(low, high);
        assert_eq!(orig, unpacked);
    }
    #[test]
    fn test_vec_alloc() {
        let mut va = VecAlloc { next: 0x30, reserved: [false; 256] };
        let v = va.alloc().unwrap();
        va.free(v);
        assert!(va.alloc().is_some());
    }
}
