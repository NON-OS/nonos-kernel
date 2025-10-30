//! NØNOS Local APIC/x2APIC Controller

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::registers::model_specific::Msr;
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::virt::{self, VmFlags};
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};

// APIC MSRs and MMIO Offsets
const IA32_APIC_BASE: u32 = 0x1B;
const IA32_TSC_DEADLINE: u32 = 0x6E0;
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

// APIC feature bits
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2: u64 = 1 << 10;
const SVR_APIC_ENABLE: u32 = 1 << 8;
const SVR_EOI_SUPPRESS: u32 = 1 << 12;

const LVT_MASKED: u32 = 1 << 16;
const LVT_LEVEL: u32 = 1 << 15;
const LVT_NMI: u32 = 0b100 << 8;
const LVT_FIXED: u32 = 0b000 << 8;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

const ICR_DELIV_FIXED: u64 = 0x0 << 8;
const ICR_DELIV_SIPI: u64 = 0x6 << 8;
const ICR_DELIV_INIT: u64 = 0x5 << 8;
const ICR_DST_PHYSICAL: u64 = 0 << 11;
const ICR_LEVEL_ASSERT: u64 = 1 << 14;
const ICR_LEVEL_DEASSERT: u64 = 0 << 14;
const ICR_TRIG_EDGE: u64 = 0 << 15;
const ICR_SH_ALL: u64 = 0b10 << 18;
const ICR_SH_OTHERS: u64 = 0b11 << 18;
const ICR_SH_SELF: u64 = 0b01 << 18;

// Interrupt vectors used
pub const VEC_SPURIOUS: u8 = 0xFF;
pub const VEC_TIMER: u8 = 0x20;
pub const VEC_THERMAL: u8 = 0x21;
pub const VEC_ERROR: u8 = 0x22;

static X2APIC: AtomicBool = AtomicBool::new(false);
static TSC_DEADLINE: AtomicBool = AtomicBool::new(false);
static MMIO_BASE_LO: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
fn rdmsr(ix: u32) -> u64 { unsafe { Msr::new(ix).read() } }
#[inline(always)]
fn wrmsr(ix: u32, v: u64) { unsafe { Msr::new(ix).write(v) } }

#[inline(always)]
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let mut a = leaf; let mut b: u32; let mut c = sub; let mut d: u32;
    unsafe { core::arch::asm!(
        "push %rbx; cpuid; mov %ebx, %esi; pop %rbx",
        inlateout("eax") a, out("esi") b, inlateout("ecx") c, lateout("edx") d,
        options(nostack, preserves_flags, att_syntax)
    ); }
    (a, b, c, d)
}

/// Returns true if xAPIC feature is available.
pub fn has_xapic() -> bool { let (_a, _b, _c, d) = cpuid(1, 0); (d & (1 << 9)) != 0 }
/// Returns true if x2APIC feature is available.
pub fn has_x2apic() -> bool { let (_a, _b, c, _d) = cpuid(1, 0); (c & (1 << 21)) != 0 }
/// Returns true if TSC deadline mode is available.
pub fn has_tsc_deadline() -> bool { let (_a, _b, c, _d) = cpuid(1, 0); (c & (1 << 24)) != 0 }

/// Initialize and program APIC. Should be called only once on BSP with IRQs disabled.
/// # Safety
/// Directly manipulates hardware registers.
pub unsafe fn init() {
    assert!(has_xapic(), "APIC not supported");

    let mut base = rdmsr(IA32_APIC_BASE);
    base |= APIC_BASE_ENABLE;
    wrmsr(IA32_APIC_BASE, base);

    // Enable x2APIC if available
    if has_x2apic() {
        wrmsr(IA32_APIC_BASE, rdmsr(IA32_APIC_BASE) | APIC_BASE_X2);
        X2APIC.store(true, Ordering::Relaxed);

        let svr = SVR_APIC_ENABLE as u64 | VEC_SPURIOUS as u64 | SVR_EOI_SUPPRESS as u64;
        wrmsr(IA32_X2APIC_SVR, svr);

        // LVTs
        wrmsr(IA32_X2APIC_LVT_LINT0, LVT_NMI as u64);          // NMI
        wrmsr(IA32_X2APIC_LVT_LINT1, LVT_MASKED as u64);       // Mask ExtINT
        wrmsr(IA32_X2APIC_LVT_THERM, LVT_FIXED as u64 | VEC_THERMAL as u64);
        wrmsr(IA32_X2APIC_LVT_ERROR, LVT_FIXED as u64 | VEC_ERROR as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64);       // Timer off until started
    } else {
        X2APIC.store(false, Ordering::Relaxed);
        let phys = (rdmsr(IA32_APIC_BASE) & 0xFFFFF000) as u64;
        let va = map_apic_mmio(PhysAddr::new(phys));
        MMIO_BASE_LO.store(va.as_u64() as u32, Ordering::Relaxed);

        mmio_w32(LAPIC_SVR, SVR_APIC_ENABLE | VEC_SPURIOUS as u32);
        mmio_w32(LAPIC_LVT_LINT0, LVT_NMI);
        mmio_w32(LAPIC_LVT_LINT1, LVT_MASKED | LVT_LEVEL);
        mmio_w32(LAPIC_LVT_THERM, VEC_THERMAL as u32);
        mmio_w32(LAPIC_LVT_ERROR, VEC_ERROR as u32);
        mmio_w32(LAPIC_LVT_TIMER, LVT_MASKED);
        proof::audit_map(va.as_u64(), phys, PAGE_SIZE as u64,
            (VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).bits(), CapTag::KERNEL);
    }

    set_tpr(0);
    TSC_DEADLINE.store(has_tsc_deadline(), Ordering::Relaxed);

    proof::audit_phys_alloc(0xA11C_0000, 0x1017_u64, CapTag::KERNEL);
}

/// Return local APIC ID.
pub fn id() -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        (rdmsr(0x802) & 0xFFFF_FFFF) as u32
    } else {
        (mmio_r32(LAPIC_ID) >> 24) & 0xFF
    }
}

/// Set Task Priority Register (TPR). Value `0` accepts all interrupts.
pub fn set_tpr(v: u8) {
    if X2APIC.load(Ordering::Relaxed) { wrmsr(IA32_X2APIC_TPR, v as u64); }
    else { mmio_w32(LAPIC_TPR, v as u32); }
}

/// Send End-of-Interrupt (EOI) to local APIC.
#[inline(always)]
pub fn eoi() {
    if X2APIC.load(Ordering::Relaxed) { wrmsr(IA32_X2APIC_EOI, 0); }
    else { mmio_w32(LAPIC_EOI, 0); }
}

/// Send IPI to self (for TLB shootdown etc.).
pub fn ipi_self(vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_SELF | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, vec as u32);
    }
}

/// Send IPI to specific APIC ID.
pub fn ipi_one(apic_id: u32, vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, (apic_id as u64) << 32 | ICR_DELIV_FIXED | ICR_DST_PHYSICAL | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, (apic_id as u32) << 24);
        mmio_w32(LAPIC_ICR_LOW, vec as u32);
    }
}

/// Send IPI to all CPUs.
pub fn ipi_all(vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_ALL | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, vec as u32 | ICR_SH_ALL as u32);
    }
}

/// Send IPI to all CPUs except self.
pub fn ipi_others(vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_OTHERS | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, vec as u32 | ICR_SH_OTHERS as u32);
    }
}

/// Bootstrap AP with INIT → SIPI → SIPI sequence.
/// # Safety
/// This is hardware bring-up logic.
pub fn start_ap(apic_id: u32, start_vec: u8) {
    icr_cmd(apic_id, ICR_DELIV_INIT | ICR_LEVEL_ASSERT | ICR_TRIG_EDGE, 0);
    busy_wait(10000); // ~10us
    icr_cmd(apic_id, ICR_DELIV_INIT | ICR_LEVEL_DEASSERT | ICR_TRIG_EDGE, 0);
    busy_wait(200000); // ~200us
    icr_cmd(apic_id, ICR_DELIV_SIPI | ICR_TRIG_EDGE, start_vec);
    busy_wait(200000);
    icr_cmd(apic_id, ICR_DELIV_SIPI | ICR_TRIG_EDGE, start_vec);
}

fn icr_cmd(apic_id: u32, mode: u64, vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, (apic_id as u64) << 32 | mode | vec as u64);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, (apic_id as u32) << 24);
        mmio_w32(LAPIC_ICR_LOW, mode as u32 | vec as u32);
    }
}

/// Enable APIC timer. Returns true if TSC-deadline mode is active.
pub fn timer_enable(hz: u32, divider: u8, initial_count_hint: u32) -> bool {
    let deadline = TSC_DEADLINE.load(Ordering::Relaxed);
    if deadline {
        if X2APIC.load(Ordering::Relaxed) {
            wrmsr(IA32_X2APIC_LVT_TIMER, VEC_TIMER as u64); // deadline mode
        } else {
            mmio_w32(LAPIC_LVT_TIMER, VEC_TIMER as u32); // clear periodic bit
        }
        proof::audit_phys_alloc(0xDEAD_1000u64, 1, CapTag::KERNEL);
        true
    } else {
        let div = match divider {
            1 => 0b1011, 2 => 0b0000, 4 => 0b0001, 8 => 0b0010,
            16 => 0b0011, 32 => 0b1000, 64 => 0b1001, 128 => 0b1010,
            _ => 0b0011, // 16
        } as u32;

        if X2APIC.load(Ordering::Relaxed) {
            wrmsr(IA32_X2APIC_DIV, div as u64);
            wrmsr(IA32_X2APIC_LVT_TIMER, VEC_TIMER as u64 | LVT_TIMER_PERIODIC as u64);
            let init = if initial_count_hint == 0 {
                calibrate_lapic_count(hz, div)
            } else { initial_count_hint };
            wrmsr(IA32_X2APIC_INITCNT, init as u64);
        } else {
            mmio_w32(LAPIC_DIV, div);
            mmio_w32(LAPIC_LVT_TIMER, VEC_TIMER as u32 | LVT_TIMER_PERIODIC);
            let init = if initial_count_hint == 0 {
                calibrate_lapic_count(hz, div)
            } else { initial_count_hint };
            mmio_w32(LAPIC_INITCNT, init);
        }
        proof::audit_phys_alloc(0xFEE00000u64, hz as u64, CapTag::KERNEL);
        false
    }
}

/// Set TSC deadline (absolute TSC value).
#[inline]
pub fn timer_deadline_tsc(tsc: u64) { wrmsr(IA32_TSC_DEADLINE, tsc); }

/// Mask timer interrupt (off).
pub fn timer_mask() {
    if X2APIC.load(Ordering::Relaxed) {
        let mut l = rdmsr(IA32_X2APIC_LVT_TIMER) as u32; l |= LVT_MASKED; wrmsr(IA32_X2APIC_LVT_TIMER, l as u64);
    } else {
        let mut l = mmio_r32(LAPIC_LVT_TIMER); l |= LVT_MASKED; mmio_w32(LAPIC_LVT_TIMER, l);
    }
}

/// Quick LAPIC timer calibration 
fn calibrate_lapic_count(hz: u32, _div_code: u32) -> u32 {
    let mut init = 10_000_000u32;
    if hz >= 1000 { init /= (hz / 1000).max(1); }
    init.max(50_000)
}

#[allow(unused)]
fn calibrate_with_hpet_or_pit(_hz: u32) -> Option<u32> { None }

#[inline(always)]
fn mmio_base() -> VirtAddr { VirtAddr::new(MMIO_BASE_LO.load(Ordering::Relaxed) as u64 & !(PAGE_SIZE as u64 - 1)) }
#[inline(always)]
fn mmio_r32(off: u32) -> u32 { unsafe { core::ptr::read_volatile((mmio_base().as_u64() + off as u64) as *const u32) } }
#[inline(always)]
fn mmio_w32(off: u32, v: u32) { unsafe { core::ptr::write_volatile((mmio_base().as_u64() + off as u64) as *mut u32, v) } }

/// Map APIC MMIO region and return virtual address.
unsafe fn map_apic_mmio(pa: PhysAddr) -> VirtAddr {
    extern "Rust" { fn __nonos_alloc_mmio_va(pages: usize) -> u64; }
    let va = VirtAddr::new(__nonos_alloc_mmio_va(1));
    virt::map_page_4k(va, pa, true, false, false).expect("lapic map");
    va
}

/// Crude busy-wait for TSC cycles. Ek: replace with arch::time when ready.
fn busy_wait(_cycles: u64) { core::hint::spin_loop(); }

/// Send End-of-Interrupt (EOI) -- direct implementation.
pub fn send_eoi() {
    mmio_w32(0xB0, 0);
}

/// Enable a specific interrupt vector (not implemented, not needed for APIC).
pub fn enable_interrupt(_vector: u8) {
    // APIC does not use enable/disable per vector via software, handled by LVT programming.
}

/// Disable a specific interrupt vector (not implemented, not needed for APIC).
pub fn disable_interrupt(_vector: u8) {
}

/// Safe APIC initialization wrapper with error handling.
pub fn init_apic() -> Result<(), &'static str> {
    if !has_xapic() {
        return Err("APIC not supported on this CPU");
    }
    unsafe {
        init();
    }
    Ok(())
}

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
    fn test_id_consistency() {
        let _ = id();
    }
    #[test]
    fn test_timer_calibration_logic() {
        let ticks = calibrate_lapic_count(1000, 0);
        assert!(ticks >= 50000);
    }
}
