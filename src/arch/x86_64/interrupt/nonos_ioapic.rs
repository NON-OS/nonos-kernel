// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! NØNOS I/O APIC Driver

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};
use lazy_static::lazy_static;

use crate::memory::virt::{self, VmFlags};
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};

// ============================================================================
// CONSTANTS
// ============================================================================

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
const IOAPICID: u32 = 0x00;
const IOAPICVER: u32 = 0x01;
const IOREDTBL0: u32 = 0x10;

const MAX_IOAPIC: usize = 8;
const MAX_GSI: usize = 1024;
const VEC_MIN: u8 = 0x30;
const VEC_MAX: u8 = 0x7E;

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoApicError {
    NotInitialized,
    AlreadyInitialized,
    GsiNotFound,
    GsiClaimedForMsi,
    VectorExhausted,
    MmioMapFailed,
    InvalidGsi,
    TooManyIoApics,
}

impl IoApicError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInitialized => "I/O APIC not initialized",
            Self::AlreadyInitialized => "I/O APIC already initialized",
            Self::GsiNotFound => "GSI not found",
            Self::GsiClaimedForMsi => "GSI claimed for MSI",
            Self::VectorExhausted => "No vectors available",
            Self::MmioMapFailed => "MMIO mapping failed",
            Self::InvalidGsi => "Invalid GSI",
            Self::TooManyIoApics => "Too many I/O APICs",
        }
    }
}

pub type IoApicResult<T> = Result<T, IoApicError>;

// ============================================================================
// REDIRECTION TABLE ENTRY
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rte {
    pub vector: u8,
    pub delivery: u8,
    pub logical: bool,
    pub active_low: bool,
    pub level_trigger: bool,
    pub masked: bool,
    pub dest_apic_id: u32,
}

impl Rte {
    pub const fn fixed(vector: u8, dest_apic_id: u32) -> Self {
        Self {
            vector,
            delivery: 0,
            logical: false,
            active_low: false,
            level_trigger: false,
            masked: true,
            dest_apic_id,
        }
    }

    pub const fn nmi(dest_apic_id: u32) -> Self {
        Self {
            vector: 0,
            delivery: 4,
            logical: false,
            active_low: false,
            level_trigger: false,
            masked: true,
            dest_apic_id,
        }
    }

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

    pub fn from_u32s(low: u32, high: u32) -> Self {
        Self {
            vector: (low & 0xFF) as u8,
            delivery: ((low >> 8) & 0x7) as u8,
            logical: (low & (1 << 11)) != 0,
            active_low: (low & (1 << 13)) != 0,
            level_trigger: (low & (1 << 15)) != 0,
            masked: (low & (1 << 16)) != 0,
            dest_apic_id: (high >> 24) & 0xFF,
        }
    }

    fn flags_bits(self) -> u32 {
        let mut f = 0u32;
        if self.logical { f |= 1 << 0; }
        if self.active_low { f |= 1 << 1; }
        if self.level_trigger { f |= 1 << 2; }
        if self.masked { f |= 1 << 3; }
        f | ((self.delivery as u32) << 8)
    }
}

impl Default for Rte {
    fn default() -> Self {
        Self::fixed(0, 0)
    }
}

// ============================================================================
// MADT STRUCTURES
// ============================================================================

#[derive(Clone, Copy, Debug)]
pub struct MadtIoApic {
    pub phys_base: u64,
    pub gsi_base: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct MadtIso {
    pub bus_irq: u8,
    pub gsi: u32,
    pub flags: IsoFlags,
}

#[derive(Clone, Copy, Debug)]
pub struct MadtNmi {
    pub cpu: u32,
    pub lint: u8,
    pub flags: IsoFlags,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct IsoFlags: u16 {
        const POLARITY_ACTIVE_HIGH = 0b00;
        const POLARITY_ACTIVE_LOW  = 0b10;
        const TRIGGER_EDGE         = 0b0000_0100;
        const TRIGGER_LEVEL        = 0b0000_1000;
    }
}

// ============================================================================
// INTERNAL STATE
// ============================================================================

#[derive(Clone, Copy)]
struct IoApicChip {
    gsi_base: u32,
    redirs: u32,
    mmio: VirtAddr,
}

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static IOAPICS: Mutex<[Option<IoApicChip>; MAX_IOAPIC]> = Mutex::new([None; MAX_IOAPIC]);
static COUNT: AtomicUsize = AtomicUsize::new(0);

struct IsoCache {
    iso: smallvec::SmallVec<[MadtIso; 16]>,
    nmis: smallvec::SmallVec<[MadtNmi; 8]>,
}

lazy_static! {
    static ref ISO: Mutex<IsoCache> = Mutex::new(IsoCache {
        iso: smallvec::SmallVec::new(),
        nmis: smallvec::SmallVec::new(),
    });
    static ref MSI_CLAIMED: Mutex<bitvec::vec::BitVec> =
        Mutex::new(bitvec::vec::BitVec::repeat(false, MAX_GSI));
}

static VEC_ALLOC: Mutex<VecAlloc> = Mutex::new(VecAlloc::new());

struct VecAlloc {
    next: u8,
    reserved: [bool; 256],
}

impl VecAlloc {
    const fn new() -> Self {
        Self { next: VEC_MIN, reserved: [false; 256] }
    }

    fn reserve(&mut self, v: u8) {
        self.reserved[v as usize] = true;
    }

    fn alloc(&mut self) -> Option<u8> {
        for _ in 0..200 {
            let v = self.next;
            self.next = if self.next >= VEC_MAX { VEC_MIN } else { self.next + 1 };
            if v >= VEC_MIN && v <= VEC_MAX && !self.reserved[v as usize] {
                self.reserved[v as usize] = true;
                return Some(v);
            }
        }
        None
    }

    fn free(&mut self, v: u8) {
        if v >= VEC_MIN && v <= VEC_MAX {
            self.reserved[v as usize] = false;
        }
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

pub unsafe fn init(ioapics: &[MadtIoApic], iso: &[MadtIso], nmis: &[MadtNmi]) -> IoApicResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(IoApicError::AlreadyInitialized);
    }

    {
        let mut cache = ISO.lock();
        cache.iso.extend_from_slice(iso);
        cache.nmis.extend_from_slice(nmis);
    }

    let mut chips = IOAPICS.lock();
    let mut n = 0usize;

    for desc in ioapics.iter().take(MAX_IOAPIC) {
        let va = map_mmio(PhysAddr::new(desc.phys_base))?;
        let ver = reg_read(va, IOAPICVER);
        let maxredir = ((ver >> 16) & 0xFF) + 1;

        chips[n] = Some(IoApicChip {
            gsi_base: desc.gsi_base,
            redirs: maxredir,
            mmio: va,
        });
        n += 1;

        proof::audit_map(
            va.as_u64(),
            desc.phys_base,
            PAGE_SIZE as u64,
            (VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).bits(),
            CapTag::KERNEL,
        );

        crate::log::logger::log_info!(
            "[IOAPIC] phys=0x{:x} gsi_base={} redirs={}",
            desc.phys_base, desc.gsi_base, maxredir
        );
    }

    COUNT.store(n, Ordering::Release);

    {
        let mut va = VEC_ALLOC.lock();
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_TIMER);
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_THERMAL);
        va.reserve(crate::arch::x86_64::interrupt::apic::VEC_ERROR);
    }

    Ok(())
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn count() -> usize {
    COUNT.load(Ordering::Acquire)
}

// ============================================================================
// MSI CLAIMING
// ============================================================================

pub fn claim_gsi_for_msi(gsi: u32) {
    let mut claimed = MSI_CLAIMED.lock();
    if (gsi as usize) < claimed.len() {
        claimed.set(gsi as usize, true);
    }
}

pub fn release_gsi_from_msi(gsi: u32) {
    let mut claimed = MSI_CLAIMED.lock();
    if (gsi as usize) < claimed.len() {
        claimed.set(gsi as usize, false);
    }
}

fn is_gsi_claimed(gsi: u32) -> bool {
    let claimed = MSI_CLAIMED.lock();
    (gsi as usize) < claimed.len() && claimed[gsi as usize]
}

// ============================================================================
// ROUTING
// ============================================================================

pub fn alloc_route(gsi: u32, dest_apic_id: u32) -> IoApicResult<(u8, Rte)> {
    if is_gsi_claimed(gsi) {
        return Err(IoApicError::GsiClaimedForMsi);
    }

    let vector = VEC_ALLOC.lock().alloc().ok_or(IoApicError::VectorExhausted)?;
    let mut rte = Rte::fixed(vector, dest_apic_id);

    if let Some(flags) = iso_flags_for(gsi) {
        if flags.contains(IsoFlags::TRIGGER_LEVEL) {
            rte.level_trigger = true;
        }
        if flags.contains(IsoFlags::POLARITY_ACTIVE_LOW) {
            rte.active_low = true;
        }
    }

    Ok((vector, rte))
}

pub fn program_route(gsi: u32, rte: Rte) -> IoApicResult<()> {
    let (chip, idx) = locate(gsi).ok_or(IoApicError::GsiNotFound)?;
    let (low, high) = rte.to_u32s();

    unsafe { redtbl_write(chip.mmio, idx, low, high); }

    proof::audit_phys_alloc(
        ((gsi as u64) << 32) | rte.vector as u64,
        ((rte.dest_apic_id as u64) << 32) | rte.flags_bits() as u64,
        CapTag::KERNEL,
    );

    Ok(())
}

pub fn mask(gsi: u32, masked: bool) -> IoApicResult<()> {
    let (chip, idx) = locate(gsi).ok_or(IoApicError::GsiNotFound)?;

    unsafe {
        let (mut low, high) = redtbl_read(chip.mmio, idx);
        if masked {
            low |= 1 << 16;
        } else {
            low &= !(1 << 16);
        }
        redtbl_write(chip.mmio, idx, low, high);
    }

    Ok(())
}

pub fn retarget(gsi: u32, dest_apic_id: u32) -> IoApicResult<()> {
    let (chip, idx) = locate(gsi).ok_or(IoApicError::GsiNotFound)?;

    unsafe {
        let (low, mut high) = redtbl_read(chip.mmio, idx);
        high &= !(0xFF << 24);
        high |= (dest_apic_id & 0xFF) << 24;
        redtbl_write(chip.mmio, idx, low, high);
    }

    Ok(())
}

pub fn free_vector(vec: u8) {
    VEC_ALLOC.lock().free(vec);
}

// ============================================================================
// QUERY / SNAPSHOT
// ============================================================================

pub fn query(gsi: u32) -> Option<Rte> {
    let (chip, idx) = locate(gsi)?;
    let (low, high) = unsafe { redtbl_read(chip.mmio, idx) };
    Some(Rte::from_u32s(low, high))
}

pub fn snapshot() -> Vec<(u32, Rte)> {
    let mut out = Vec::new();
    let chips = IOAPICS.lock();

    for chip in chips.iter().flatten() {
        for i in 0..chip.redirs {
            let (low, high) = unsafe { redtbl_read(chip.mmio, i) };
            out.push((chip.gsi_base + i, Rte::from_u32s(low, high)));
        }
    }

    out
}

pub fn restore(snap: &[(u32, Rte)]) {
    for (gsi, rte) in snap {
        let _ = program_route(*gsi, Rte { masked: true, ..*rte });
    }
}

// ============================================================================
// STATUS
// ============================================================================

#[derive(Debug, Clone)]
pub struct IoApicStatus {
    pub initialized: bool,
    pub count: usize,
    pub total_gsis: u32,
}

pub fn status() -> IoApicStatus {
    let chips = IOAPICS.lock();
    let mut total_gsis = 0u32;

    for chip in chips.iter().flatten() {
        total_gsis += chip.redirs;
    }

    IoApicStatus {
        initialized: is_initialized(),
        count: count(),
        total_gsis,
    }
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

fn iso_flags_for(gsi: u32) -> Option<IsoFlags> {
    let cache = ISO.lock();
    cache.iso.iter().find(|e| e.gsi == gsi).map(|e| e.flags)
}

fn locate(gsi: u32) -> Option<(IoApicChip, u32)> {
    let chips = IOAPICS.lock();
    for chip in chips.iter().flatten() {
        let end = chip.gsi_base + chip.redirs;
        if gsi >= chip.gsi_base && gsi < end {
            return Some((*chip, gsi - chip.gsi_base));
        }
    }
    None
}

unsafe fn map_mmio(pa: PhysAddr) -> IoApicResult<VirtAddr> {
    extern "Rust" {
        fn __nonos_alloc_mmio_va(pages: usize) -> u64;
    }

    let va = VirtAddr::new(__nonos_alloc_mmio_va(1));
    virt::map_page_4k(va, pa, true, false, false)
        .map_err(|_| IoApicError::MmioMapFailed)?;

    Ok(va)
}

#[inline(always)]
fn reg_write(base: VirtAddr, index: u32, val: u32) {
    unsafe {
        let sel = (base.as_u64() + IOREGSEL) as *mut u32;
        let win = (base.as_u64() + IOWIN) as *mut u32;
        core::ptr::write_volatile(sel, index);
        core::ptr::write_volatile(win, val);
    }
}

#[inline(always)]
fn reg_read(base: VirtAddr, index: u32) -> u32 {
    unsafe {
        let sel = (base.as_u64() + IOREGSEL) as *mut u32;
        let win = (base.as_u64() + IOWIN) as *const u32;
        core::ptr::write_volatile(sel, index);
        core::ptr::read_volatile(win)
    }
}

unsafe fn redtbl_write(base: VirtAddr, i: u32, low: u32, high: u32) {
    reg_write(base, IOREDTBL0 + (i * 2) + 1, high);
    reg_write(base, IOREDTBL0 + (i * 2), low);
}

unsafe fn redtbl_read(base: VirtAddr, i: u32) -> (u32, u32) {
    let high = reg_read(base, IOREDTBL0 + (i * 2) + 1);
    let low = reg_read(base, IOREDTBL0 + (i * 2));
    (low, high)
}

// ============================================================================
// TESTS
// ============================================================================

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
    fn test_rte_level_trigger() {
        let mut rte = Rte::fixed(0x33, 0);
        rte.level_trigger = true;
        rte.active_low = true;
        let (low, _) = rte.to_u32s();
        assert!(low & (1 << 15) != 0);
        assert!(low & (1 << 13) != 0);
    }

    #[test]
    fn test_vec_alloc() {
        let mut va = VecAlloc::new();
        let v = va.alloc().unwrap();
        assert!(v >= VEC_MIN && v <= VEC_MAX);
        va.free(v);
        assert!(!va.reserved[v as usize]);
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(IoApicError::GsiNotFound.as_str(), "GSI not found");
        assert_eq!(IoApicError::VectorExhausted.as_str(), "No vectors available");
    }
}
