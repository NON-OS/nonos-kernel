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
//
//! NØNOS Local APIC/x2APIC Controller

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use x86_64::registers::model_specific::Msr;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::virt::{self, VmFlags};
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};

// ============================================================================
// ERROR HANDLING
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApicError {
    NotSupported,
    AlreadyInitialized,
    NotInitialized,
    X2ApicNotSupported,
    MmioMapFailed,
    InvalidVector,
    IcrBusy,
}

impl ApicError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotSupported => "APIC not supported",
            Self::AlreadyInitialized => "APIC already initialized",
            Self::NotInitialized => "APIC not initialized",
            Self::X2ApicNotSupported => "x2APIC not supported",
            Self::MmioMapFailed => "APIC MMIO mapping failed",
            Self::InvalidVector => "Invalid interrupt vector",
            Self::IcrBusy => "ICR busy timeout",
        }
    }

    pub const fn to_errno(self) -> i32 {
        match self {
            Self::NotSupported | Self::X2ApicNotSupported => -19,
            Self::AlreadyInitialized => -16,
            Self::NotInitialized | Self::MmioMapFailed => -5,
            Self::InvalidVector => -22,
            Self::IcrBusy => -16,
        }
    }
}

pub type ApicResult<T> = Result<T, ApicError>;

// ============================================================================
// CONSTANTS - MSRs
// ============================================================================

const IA32_APIC_BASE: u32 = 0x1B;
const IA32_TSC_DEADLINE: u32 = 0x6E0;
const IA32_X2APIC_APICID: u32 = 0x802;
const IA32_X2APIC_TPR: u32 = 0x808;
const IA32_X2APIC_EOI: u32 = 0x80B;
const IA32_X2APIC_SVR: u32 = 0x80F;
const IA32_X2APIC_ICR: u32 = 0x830;
const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
const IA32_X2APIC_LVT_THERM: u32 = 0x833;
const IA32_X2APIC_LVT_LINT0: u32 = 0x835;
const IA32_X2APIC_LVT_LINT1: u32 = 0x836;
const IA32_X2APIC_LVT_ERROR: u32 = 0x837;
const IA32_X2APIC_DIV: u32 = 0x83E;
const IA32_X2APIC_INITCNT: u32 = 0x838;
const IA32_X2APIC_CURRCNT: u32 = 0x839;

// ============================================================================
// CONSTANTS - MMIO OFFSETS
// ============================================================================

const LAPIC_ID: u32 = 0x020;
const LAPIC_VER: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080;
const LAPIC_EOI: u32 = 0x0B0;
const LAPIC_SVR: u32 = 0x0F0;
const LAPIC_ICR_LOW: u32 = 0x300;
const LAPIC_ICR_HIGH: u32 = 0x310;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_THERM: u32 = 0x330;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_LVT_LINT1: u32 = 0x360;
const LAPIC_LVT_ERROR: u32 = 0x370;
const LAPIC_INITCNT: u32 = 0x380;
const LAPIC_CURRCNT: u32 = 0x390;
const LAPIC_DIV: u32 = 0x3E0;

// ============================================================================
// CONSTANTS - FLAGS
// ============================================================================

const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2: u64 = 1 << 10;
const SVR_APIC_ENABLE: u32 = 1 << 8;
const SVR_EOI_SUPPRESS: u32 = 1 << 12;

const LVT_MASKED: u32 = 1 << 16;
const LVT_LEVEL: u32 = 1 << 15;
const LVT_NMI: u32 = 0b100 << 8;
const LVT_FIXED: u32 = 0b000 << 8;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const LVT_TIMER_TSC_DEADLINE: u32 = 2 << 17;

const ICR_DELIV_FIXED: u64 = 0x0 << 8;
const ICR_DELIV_SIPI: u64 = 0x6 << 8;
const ICR_DELIV_INIT: u64 = 0x5 << 8;
const ICR_DST_PHYSICAL: u64 = 0 << 11;
const ICR_LEVEL_ASSERT: u64 = 1 << 14;
const ICR_LEVEL_DEASSERT: u64 = 0 << 14;
const ICR_TRIG_EDGE: u64 = 0 << 15;
const ICR_SH_NONE: u64 = 0b00 << 18;
const ICR_SH_SELF: u64 = 0b01 << 18;
const ICR_SH_ALL: u64 = 0b10 << 18;
const ICR_SH_OTHERS: u64 = 0b11 << 18;
const ICR_BUSY: u32 = 1 << 12;

// ============================================================================
// PUBLIC VECTORS
// ============================================================================

pub const VEC_SPURIOUS: u8 = 0xFF;
pub const VEC_TIMER: u8 = 0x20;
pub const VEC_THERMAL: u8 = 0x21;
pub const VEC_ERROR: u8 = 0x22;

// ============================================================================
// STATE
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static X2APIC_MODE: AtomicBool = AtomicBool::new(false);
static TSC_DEADLINE_MODE: AtomicBool = AtomicBool::new(false);
static MMIO_BASE: AtomicU32 = AtomicU32::new(0);
static CACHED_ID: AtomicU32 = AtomicU32::new(0);
static CURRENT_TPR: AtomicU8 = AtomicU8::new(0);

// ============================================================================
// MSR/CPUID HELPERS
// ============================================================================

#[inline(always)]
fn rdmsr(msr: u32) -> u64 {
    unsafe { Msr::new(msr).read() }
}

#[inline(always)]
fn wrmsr(msr: u32, val: u64) {
    unsafe { Msr::new(msr).write(val) }
}

#[inline(always)]
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, sub) };
    (r.eax, r.ebx, r.ecx, r.edx)
}

// ============================================================================
// FEATURE DETECTION
// ============================================================================

pub fn has_xapic() -> bool {
    let (_, _, _, edx) = cpuid(1, 0);
    (edx & (1 << 9)) != 0
}

pub fn has_x2apic() -> bool {
    let (_, _, ecx, _) = cpuid(1, 0);
    (ecx & (1 << 21)) != 0
}

pub fn has_tsc_deadline() -> bool {
    let (_, _, ecx, _) = cpuid(1, 0);
    (ecx & (1 << 24)) != 0
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn is_x2apic() -> bool {
    X2APIC_MODE.load(Ordering::Acquire)
}

#[inline]
pub fn supports_tsc_deadline() -> bool {
    TSC_DEADLINE_MODE.load(Ordering::Acquire)
}

// ============================================================================
// INITIALIZATION
// ============================================================================

pub unsafe fn init() -> ApicResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(ApicError::AlreadyInitialized);
    }

    if !has_xapic() {
        INITIALIZED.store(false, Ordering::SeqCst);
        return Err(ApicError::NotSupported);
    }

    let mut base = rdmsr(IA32_APIC_BASE);
    base |= APIC_BASE_ENABLE;
    wrmsr(IA32_APIC_BASE, base);

    if has_x2apic() {
        wrmsr(IA32_APIC_BASE, rdmsr(IA32_APIC_BASE) | APIC_BASE_X2);
        X2APIC_MODE.store(true, Ordering::Release);
        init_x2apic();
    } else {
        X2APIC_MODE.store(false, Ordering::Release);
        init_xapic()?;
    }

    set_tpr(0);
    TSC_DEADLINE_MODE.store(has_tsc_deadline(), Ordering::Release);

    let apic_id = read_id_internal();
    CACHED_ID.store(apic_id, Ordering::Release);

    proof::audit_phys_alloc(0xA11C_0000, 0x1017_u64, CapTag::KERNEL);

    crate::log::logger::log_info!(
        "[APIC] mode={} id={} tsc_deadline={}",
        if is_x2apic() { "x2APIC" } else { "xAPIC" },
        apic_id,
        supports_tsc_deadline()
    );

    Ok(())
}

fn init_x2apic() {
    let svr = SVR_APIC_ENABLE as u64 | VEC_SPURIOUS as u64 | SVR_EOI_SUPPRESS as u64;
    wrmsr(IA32_X2APIC_SVR, svr);

    wrmsr(IA32_X2APIC_LVT_LINT0, LVT_NMI as u64);
    wrmsr(IA32_X2APIC_LVT_LINT1, LVT_MASKED as u64);
    wrmsr(IA32_X2APIC_LVT_THERM, LVT_FIXED as u64 | VEC_THERMAL as u64);
    wrmsr(IA32_X2APIC_LVT_ERROR, LVT_FIXED as u64 | VEC_ERROR as u64);
    wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);
}

unsafe fn init_xapic() -> ApicResult<()> {
    let phys = (rdmsr(IA32_APIC_BASE) & 0xFFFF_F000) as u64;
    let va = map_apic_mmio(PhysAddr::new(phys))?;
    MMIO_BASE.store(va.as_u64() as u32, Ordering::Release);

    mmio_w32(LAPIC_SVR, SVR_APIC_ENABLE | VEC_SPURIOUS as u32);
    mmio_w32(LAPIC_LVT_LINT0, LVT_NMI);
    mmio_w32(LAPIC_LVT_LINT1, LVT_MASKED | LVT_LEVEL);
    mmio_w32(LAPIC_LVT_THERM, VEC_THERMAL as u32);
    mmio_w32(LAPIC_LVT_ERROR, VEC_ERROR as u32);
    mmio_w32(LAPIC_LVT_TIMER, LVT_MASKED);

    proof::audit_map(
        va.as_u64(),
        phys,
        PAGE_SIZE as u64,
        (VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).bits(),
        CapTag::KERNEL,
    );

    Ok(())
}

pub fn init_apic() -> ApicResult<()> {
    unsafe { init() }
}

// ============================================================================
// BASIC OPERATIONS
// ============================================================================

pub fn id() -> u32 {
    CACHED_ID.load(Ordering::Acquire)
}

fn read_id_internal() -> u32 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        (rdmsr(IA32_X2APIC_APICID) & 0xFFFF_FFFF) as u32
    } else {
        (mmio_r32(LAPIC_ID) >> 24) & 0xFF
    }
}

pub fn set_tpr(priority: u8) {
    CURRENT_TPR.store(priority, Ordering::Release);
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_TPR, priority as u64);
    } else {
        mmio_w32(LAPIC_TPR, priority as u32);
    }
}

pub fn get_tpr() -> u8 {
    CURRENT_TPR.load(Ordering::Acquire)
}

#[inline(always)]
pub fn eoi() {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_EOI, 0);
    } else {
        mmio_w32(LAPIC_EOI, 0);
    }
}

pub fn send_eoi() {
    eoi();
}

pub fn version() -> u32 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        (rdmsr(0x803) & 0xFF) as u32
    } else {
        mmio_r32(LAPIC_VER) & 0xFF
    }
}

pub fn max_lvt() -> u8 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        ((rdmsr(0x803) >> 16) & 0xFF) as u8
    } else {
        ((mmio_r32(LAPIC_VER) >> 16) & 0xFF) as u8
    }
}

// ============================================================================
// IPI OPERATIONS
// ============================================================================

pub fn ipi_self(vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_SELF | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, ICR_SH_SELF as u32 | vec as u32);
    }
}

pub fn ipi_one(apic_id: u32, vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(
            IA32_X2APIC_ICR,
            (apic_id as u64) << 32 | ICR_DELIV_FIXED | ICR_DST_PHYSICAL | ICR_SH_NONE | (vec as u64),
        );
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, apic_id << 24);
        mmio_w32(LAPIC_ICR_LOW, vec as u32);
    }
}

pub fn ipi_all(vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_ALL | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, ICR_SH_ALL as u32 | vec as u32);
    }
}

pub fn ipi_others(vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_OTHERS | (vec as u64));
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, ICR_SH_OTHERS as u32 | vec as u32);
    }
}

fn wait_icr_idle() {
    for _ in 0..100_000 {
        if (mmio_r32(LAPIC_ICR_LOW) & ICR_BUSY) == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

// ============================================================================
// AP STARTUP
// ============================================================================

pub fn start_ap(apic_id: u32, start_page: u8) {
    icr_send(apic_id, ICR_DELIV_INIT | ICR_LEVEL_ASSERT | ICR_TRIG_EDGE, 0);
    delay_us(10);

    icr_send(apic_id, ICR_DELIV_INIT | ICR_LEVEL_DEASSERT | ICR_TRIG_EDGE, 0);
    delay_us(200);

    icr_send(apic_id, ICR_DELIV_SIPI | ICR_TRIG_EDGE, start_page);
    delay_us(200);

    icr_send(apic_id, ICR_DELIV_SIPI | ICR_TRIG_EDGE, start_page);
}

fn icr_send(apic_id: u32, mode: u64, vec: u8) {
    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_ICR, (apic_id as u64) << 32 | mode | vec as u64);
    } else {
        wait_icr_idle();
        mmio_w32(LAPIC_ICR_HIGH, apic_id << 24);
        mmio_w32(LAPIC_ICR_LOW, mode as u32 | vec as u32);
    }
}

fn delay_us(us: u64) {
    for _ in 0..(us * 1000) {
        core::hint::spin_loop();
    }
}

// ============================================================================
// TIMER
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}

pub fn timer_enable(hz: u32, divider: u8) -> TimerMode {
    if TSC_DEADLINE_MODE.load(Ordering::Acquire) {
        if X2APIC_MODE.load(Ordering::Acquire) {
            wrmsr(IA32_X2APIC_LVT_TIMER, LVT_TIMER_TSC_DEADLINE as u64 | VEC_TIMER as u64);
        } else {
            mmio_w32(LAPIC_LVT_TIMER, LVT_TIMER_TSC_DEADLINE | VEC_TIMER as u32);
        }
        proof::audit_phys_alloc(0xDEAD_1000u64, 1, CapTag::KERNEL);
        return TimerMode::TscDeadline;
    }

    let div_code = divider_to_code(divider);
    let init_count = calibrate_timer(hz);

    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_DIV, div_code as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, LVT_TIMER_PERIODIC as u64 | VEC_TIMER as u64);
        wrmsr(IA32_X2APIC_INITCNT, init_count as u64);
    } else {
        mmio_w32(LAPIC_DIV, div_code);
        mmio_w32(LAPIC_LVT_TIMER, LVT_TIMER_PERIODIC | VEC_TIMER as u32);
        mmio_w32(LAPIC_INITCNT, init_count);
    }

    proof::audit_phys_alloc(0xFEE00000u64, hz as u64, CapTag::KERNEL);
    TimerMode::Periodic
}

pub fn timer_oneshot(ticks: u32, divider: u8) {
    let div_code = divider_to_code(divider);

    if X2APIC_MODE.load(Ordering::Acquire) {
        wrmsr(IA32_X2APIC_DIV, div_code as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, VEC_TIMER as u64);
        wrmsr(IA32_X2APIC_INITCNT, ticks as u64);
    } else {
        mmio_w32(LAPIC_DIV, div_code);
        mmio_w32(LAPIC_LVT_TIMER, VEC_TIMER as u32);
        mmio_w32(LAPIC_INITCNT, ticks);
    }
}

#[inline]
pub fn timer_deadline_tsc(tsc: u64) {
    wrmsr(IA32_TSC_DEADLINE, tsc);
}

pub fn timer_mask() {
    if X2APIC_MODE.load(Ordering::Acquire) {
        let val = rdmsr(IA32_X2APIC_LVT_TIMER) as u32 | LVT_MASKED;
        wrmsr(IA32_X2APIC_LVT_TIMER, val as u64);
    } else {
        let val = mmio_r32(LAPIC_LVT_TIMER) | LVT_MASKED;
        mmio_w32(LAPIC_LVT_TIMER, val);
    }
}

pub fn timer_unmask() {
    if X2APIC_MODE.load(Ordering::Acquire) {
        let val = rdmsr(IA32_X2APIC_LVT_TIMER) as u32 & !LVT_MASKED;
        wrmsr(IA32_X2APIC_LVT_TIMER, val as u64);
    } else {
        let val = mmio_r32(LAPIC_LVT_TIMER) & !LVT_MASKED;
        mmio_w32(LAPIC_LVT_TIMER, val);
    }
}

pub fn timer_current() -> u32 {
    if X2APIC_MODE.load(Ordering::Acquire) {
        rdmsr(IA32_X2APIC_CURRCNT) as u32
    } else {
        mmio_r32(LAPIC_CURRCNT)
    }
}

fn divider_to_code(div: u8) -> u32 {
    match div {
        1 => 0b1011,
        2 => 0b0000,
        4 => 0b0001,
        8 => 0b0010,
        16 => 0b0011,
        32 => 0b1000,
        64 => 0b1001,
        128 => 0b1010,
        _ => 0b0011,
    }
}

fn calibrate_timer(hz: u32) -> u32 {
    let mut init = 10_000_000u32;
    if hz >= 1000 {
        init /= (hz / 1000).max(1);
    }
    init.max(50_000)
}

// ============================================================================
// LVT CONFIGURATION
// ============================================================================

pub fn enable_interrupt(_vector: u8) {}
pub fn disable_interrupt(_vector: u8) {}

// ============================================================================
// STATUS
// ============================================================================

#[derive(Debug, Clone)]
pub struct ApicStatus {
    pub initialized: bool,
    pub x2apic: bool,
    pub tsc_deadline: bool,
    pub id: u32,
    pub version: u32,
    pub max_lvt: u8,
    pub tpr: u8,
}

pub fn status() -> ApicStatus {
    ApicStatus {
        initialized: is_initialized(),
        x2apic: is_x2apic(),
        tsc_deadline: supports_tsc_deadline(),
        id: id(),
        version: if is_initialized() { version() } else { 0 },
        max_lvt: if is_initialized() { max_lvt() } else { 0 },
        tpr: get_tpr(),
    }
}

// ============================================================================
// MMIO HELPERS
// ============================================================================

#[inline(always)]
fn mmio_base() -> VirtAddr {
    VirtAddr::new((MMIO_BASE.load(Ordering::Acquire) as u64) & !(PAGE_SIZE as u64 - 1))
}

#[inline(always)]
fn mmio_r32(offset: u32) -> u32 {
    unsafe { core::ptr::read_volatile((mmio_base().as_u64() + offset as u64) as *const u32) }
}

#[inline(always)]
fn mmio_w32(offset: u32, val: u32) {
    unsafe { core::ptr::write_volatile((mmio_base().as_u64() + offset as u64) as *mut u32, val) }
}

unsafe fn map_apic_mmio(pa: PhysAddr) -> ApicResult<VirtAddr> {
    extern "Rust" {
        fn __nonos_alloc_mmio_va(pages: usize) -> u64;
    }

    let va = VirtAddr::new(__nonos_alloc_mmio_va(1));
    virt::map_page_4k(va, pa, true, false, false).map_err(|_| ApicError::MmioMapFailed)?;
    Ok(va)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_detection() {
        let _ = has_xapic();
        let _ = has_x2apic();
        let _ = has_tsc_deadline();
    }

    #[test]
    fn test_divider_codes() {
        assert_eq!(divider_to_code(1), 0b1011);
        assert_eq!(divider_to_code(16), 0b0011);
        assert_eq!(divider_to_code(128), 0b1010);
        assert_eq!(divider_to_code(99), 0b0011);
    }

    #[test]
    fn test_calibration() {
        let ticks = calibrate_timer(1000);
        assert!(ticks >= 50000);
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(ApicError::NotSupported.as_str(), "APIC not supported");
        assert_eq!(ApicError::IcrBusy.as_str(), "ICR busy timeout");
    }
}
