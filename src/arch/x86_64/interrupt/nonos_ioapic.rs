// arch/x86_64/interrupt/ioapic.rs
//
// NØNOS I/O APIC.
// - Multi-IOAPIC registry
// - ACPI MADT parsing hooks: ISO (Interrupt Source Override) + NMI entries
// - Correct edge/level + polarity from firmware; safe RTE read-modify-write
// - Vector allocator (pluggable), reserved ranges, per-CPU affinity
// - Mask/unmask, retarget, query, snapshot/restore
// - MSI/MSI-X aware (do not double-route if device moved to MSI)
// - Audited via memory::proof (public commit)
//
// Zero-state. No persistence. Call init() in early boot with IRQs disabled.

#![allow(dead_code)]

use alloc::format;

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use lazy_static::lazy_static;

use crate::memory::virt::{self, VmFlags};
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};

/// ——————————————————— Registers (4K MMIO window) ———————————————————
const IOREGSEL: u64 = 0x00; // selector (u32)
const IOWIN:    u64 = 0x10; // data     (u32)
const IOAPICID:  u32 = 0x00;
const IOAPICVER: u32 = 0x01;
const IOAPICARB: u32 = 0x02;
const IOREDTBL0: u32 = 0x10; // two u32 per entry: low (even), high (odd)

/// ——————————————————— Redirection Table Entry model ———————————————————
/// Bits (low dword):
///  7:0   vector
/// 10:8   delivery mode (000=fixed, 100=NMI)
/// 11     dest mode (0=physical, 1=logical)
/// 12     delivery status (RO)
/// 13     polarity (0=high, 1=low)
/// 14     remote IRR (RO)
/// 15     trigger (0=edge, 1=level)
/// 16     mask (1=masked)
#[derive(Clone, Copy, Debug)]
pub struct Rte {
    pub vector: u8,
    pub delivery: u8, // 0=fixed, 4=NMI
    pub logical: bool,
    pub active_low: bool,
    pub level_trigger: bool,
    pub masked: bool,
    pub dest_apic_id: u32, // physical: 8 bits (xAPIC); logical: full mask (x2APIC flat/cluster)
}

impl Rte {
    pub const fn fixed(vector: u8, dest_apic_id: u32) -> Self {
        Self {
            vector, delivery: 0, logical: false,
            active_low: false, level_trigger: false, masked: true,
            dest_apic_id,
        }
    }
    fn to_u32s(self) -> (u32, u32) {
        let mut low = self.vector as u32;
        low |= (self.delivery as u32) << 8;
        if self.logical { low |= 1 << 11; }
        if self.active_low { low |= 1 << 13; }
        if self.level_trigger { low |= 1 << 15; }
        if self.masked { low |= 1 << 16; }
        let high = (self.dest_apic_id & 0xFF) << 24; // physical mode
        (low, high)
    }
    fn from_u32s(low: u32, high: u32) -> Self {
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

/// ——————————————————— ACPI MADT descriptors we consume ———————————————————
/// Provide these from your ACPI parser (don’t make this module parse tables).
#[derive(Clone, Copy, Debug)]
pub struct MadtIoApic { pub phys_base: u64, pub gsi_base: u32 }
#[derive(Clone, Debug, Copy)]
pub struct MadtIso    { pub bus_irq: u8, pub gsi: u32, pub flags: IsoFlags }
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

/// ——————————————————— IOAPIC topology registry ———————————————————
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
    /// ISA overrides and NMI policy (from MADT)
    static ref ISO: Mutex<VecIso> = Mutex::new(VecIso { 
        iso: smallvec::SmallVec::new(), 
        nmis: smallvec::SmallVec::new() 
    });
}

/// Simple vector allocator with a reserved range (pluggable later).
/// Default: allocate in 0x30..0x7F, skipping 0xFF (spurious) and vectors you mark reserved.
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
    /// Devices that switched to MSI/MSI-X (we won't also route their GSIs)
    static ref MSI_CLAIMED_GSI: Mutex<bitvec::vec::BitVec> = Mutex::new(bitvec::vec::BitVec::repeat(false, 1024));
}

/// ——————————————————— Public init ———————————————————

/// Map and register IOAPICs (MMIO UC). Provide MADT IOAPIC list first.
pub unsafe fn init(ioapics: &[MadtIoApic], iso: &[MadtIso], nmis: &[MadtNmi]) {
    // Save ISO/NMI policy
    {
        let mut v = ISO.lock();
        v.iso.extend_from_slice(iso);
        v.nmis.extend_from_slice(nmis);
    }

    // Map chips
    let mut t = IOAPICS.lock();
    let mut n = 0usize;
    for d in ioapics.iter().take(MAX_IOAPIC) {
        let va = map_mmio(PhysAddr::new(d.phys_base));
        let ver = reg_read(va, IOAPICVER);
        let maxredir = ((ver >> 16) & 0xFF) + 1;
        t[n] = Some(IoApicChip { gsi_base: d.gsi_base, redirs: maxredir, mmio: va });
        n += 1;

        proof::audit_map(va.as_u64(), d.phys_base, PAGE_SIZE as u64, (VmFlags::RW|VmFlags::NX|VmFlags::GLOBAL|VmFlags::PCD).bits(), CapTag::KERNEL);
        crate::log::logger::try_get_logger().map(|l| l.log(&format!(
            "[IOAPIC] mmio=0x{:x} gsi_base={} redirs={}", d.phys_base, d.gsi_base, maxredir
        )));
    }
    COUNT.store(n, Ordering::Relaxed);

    // Reserve vectors we know are in use
    {
        let mut va = VEC_ALLOC.lock();
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_TIMER);
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_THERMAL);
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_ERROR);
        // add more reserved IDs here as you assign them
    }
}

/// Count of IOAPICs registered.
pub fn count() -> usize { COUNT.load(Ordering::Relaxed) }

/// Claim a GSI for MSI/MSI-X path (so we don’t also program IOAPIC).
pub fn claim_gsi_for_msi(gsi: u32) { let mut g = MSI_CLAIMED_GSI.lock(); if (gsi as usize) < g.len() { g.set(gsi as usize, true); } }

/// Allocate a vector for a given GSI with proper flags derived from ISO table.
/// Returns (vector, RTE) preconfigured and masked; caller should unmask after handler installed.
pub fn alloc_route(gsi: u32, dest_apic_id: u32) -> Result<(u8, Rte), ()> {
    ensure_not_msi(gsi)?;
    let mut va = VEC_ALLOC.lock();
    let vector = va.alloc().ok_or(())?;

    let mut rte = Rte::fixed(vector, dest_apic_id);
    // Derive polarity/trigger from ISO (typical ISA: IRQ0..15) or fall back to edge/high
    if let Some(f) = iso_flags_for(gsi) {
        if f.contains(IsoFlags::TRIGGER_LEVEL) { rte.level_trigger = true; }
        if f.contains(IsoFlags::POLARITY_ACTIVE_LOW) { rte.active_low = true; }
    }
    rte.masked = true;

    Ok((vector, rte))
}

/// Program the route (write RTE). Safe RMW sequence.
/// We always write HIGH then LOW (Intel SDM). For level triggers, masking/unmask handled by caller.
pub fn program_route(gsi: u32, rte: Rte) -> Result<(), ()> {
    let (chip, idx) = locate(gsi).ok_or(())?;
    let (low, high) = rte.to_u32s();
    unsafe { redtbl_write(chip.mmio, idx, low, high); }
    proof::audit_phys_alloc(((gsi as u64)<<32) | rte.vector as u64, ((rte.dest_apic_id as u64)<<32) | rte_flags_bits(rte) as u64, CapTag::KERNEL);
    Ok(())
}

/// Mask/unmask a GSI. For **level**-triggered, ensure your handler EOI’d the LAPIC before unmasking.
pub fn mask(gsi: u32, masked: bool) -> Result<(), ()> {
    let (chip, idx) = locate(gsi).ok_or(())?;
    unsafe {
        let (mut low, high) = redtbl_read(chip.mmio, idx);
        if masked { low |= 1<<16 } else { low &= !(1<<16) }
        redtbl_write(chip.mmio, idx, low, high);
    }
    Ok(())
}

/// Retarget destination APIC ID. Useful for CPU affinity changes.
pub fn retarget(gsi: u32, dest_apic_id: u32) -> Result<(), ()> {
    let (chip, idx) = locate(gsi).ok_or(())?;
    unsafe {
        let (low, mut high) = redtbl_read(chip.mmio, idx);
        high &= !(0xFF << 24);
        high |= (dest_apic_id & 0xFF) << 24;
        redtbl_write(chip.mmio, idx, low, high);
    }
    Ok(())
}

/// Free a vector allocated by alloc_route (call after mask+program is undone).
pub fn free_vector(vec: u8) { VEC_ALLOC.lock().free(vec); }

/// Query current RTE.
pub fn query(gsi: u32) -> Option<Rte> {
    let (chip, idx) = locate(gsi)?;
    let (low, high) = unsafe { redtbl_read(chip.mmio, idx) };
    Some(Rte::from_u32s(low, high))
}

/// Snapshot all RTEs (for debug or suspend). Returns (gsi, rte) pairs.
pub fn snapshot() -> alloc::vec::Vec<(u32, Rte)> {
    let mut out = alloc::vec::Vec::new();
    let t = IOAPICS.lock();
    for chip in t.iter().flatten() {
        for i in 0..chip.redirs {
            let (low, high) = unsafe { redtbl_read(chip.mmio, i) };
            out.push((chip.gsi_base + i, Rte::from_u32s(low, high)));
        }
    }
    out
}

/// Restore snapshot (masked). Useful for resume flows.
pub fn restore(snap: &[(u32, Rte)]) {
    for (gsi, rte) in snap {
        let _ = program_route(*gsi, Rte { masked: true, ..*rte });
    }
}

// ——————————————————— Internals ———————————————————

fn ensure_not_msi(gsi: u32) -> Result<(), ()> {
    let g = MSI_CLAIMED_GSI.lock();
    if (gsi as usize) < g.len() && g[gsi as usize] { return Err(()); }
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

unsafe fn map_mmio(pa: PhysAddr) -> VirtAddr {
    extern "Rust" { fn __nonos_alloc_mmio_va(pages: usize) -> u64; }
    let va = VirtAddr::new(__nonos_alloc_mmio_va(1));
    virt::map4k_at(va, pa, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).expect("ioapic map");
    va
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
    // Per SDM, program high then low. For level-triggered, keep your handler EOI rules!
    reg_write(base, IOREDTBL0 + (i * 2) + 1, high);
    reg_write(base, IOREDTBL0 + (i * 2) + 0, low);
}
unsafe fn redtbl_read(base: VirtAddr, i: u32) -> (u32, u32) {
    let high = reg_read(base, IOREDTBL0 + (i * 2) + 1);
    let low  = reg_read(base, IOREDTBL0 + (i * 2) + 0);
    (low, high)
}

/// For proof event packing
fn rte_flags_bits(r: Rte) -> u32 {
    let mut f = 0u32;
    if r.logical { f |= 1<<0; }
    if r.active_low { f |= 1<<1; }
    if r.level_trigger { f |= 1<<2; }
    if r.masked { f |= 1<<3; }
    f | ((r.delivery as u32) << 8)
}
