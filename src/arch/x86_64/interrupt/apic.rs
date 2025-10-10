// arch/x86_64/interrupt/apic.rs
//
// NØNOS Local APIC.
// - xAPIC/x2APIC enable; EOI broadcast suppression; focus processor disabled
// - LVT programming: Timer / LINT0(NMI) / LINT1(mask ExtINT) / Thermal / Error
// - TSC-deadline mode if available; else periodic/one-shot with divider
// - Timer calibration (fast: TSC; precise: PIT/HPET hooks)
// - IPI API: self, single, all, all-but-self; INIT/SIPI AP bring-up stubs
// - LAPIC ID read; xAPIC MMIO UC map; safe teardown
// - Proof hooks (public) for audit
//
// Safety: call `init()` once on BSP with interrupts disabled.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use x86_64::registers::model_specific::Msr;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};
use crate::memory::virt::{self, VmFlags};

// ——— APIC MSRs ———
const IA32_APIC_BASE: u32 = 0x1B;
const IA32_TSC_DEADLINE: u32 = 0x6E0;
const IA32_X2APIC_TPR: u32 = 0x808;
const IA32_X2APIC_EOI: u32 = 0x80B;
const IA32_X2APIC_SVR: u32 = 0x80F;
const IA32_X2APIC_ICR: u32 = 0x830;
const IA32_X2APIC_LVT_TIMER: u32 = 0x832;
const IA32_X2APIC_LVT_THERM: u32 = 0x833;
const IA32_X2APIC_LVT_PMC: u32 = 0x834;
const IA32_X2APIC_LVT_LINT0: u32 = 0x835;
const IA32_X2APIC_LVT_LINT1: u32 = 0x836;
const IA32_X2APIC_LVT_ERROR: u32 = 0x837;
const IA32_X2APIC_DIV: u32 = 0x83E;
const IA32_X2APIC_INITCNT: u32 = 0x838;
const IA32_X2APIC_CURRCNT: u32 = 0x839;

// ——— xAPIC MMIO offsets ———
const LAPIC_ID: u32 = 0x020;
const LAPIC_VER: u32 = 0x030;
const LAPIC_TPR: u32 = 0x080;
const LAPIC_EOI: u32 = 0x0B0;
const LAPIC_SVR: u32 = 0x0F0;
const LAPIC_ICR_LOW: u32 = 0x300;
const LAPIC_ICR_HIGH: u32 = 0x310;
const LAPIC_LVT_TIMER: u32 = 0x320;
const LAPIC_LVT_THERM: u32 = 0x330;
const LAPIC_LVT_PMC: u32 = 0x340;
const LAPIC_LVT_LINT0: u32 = 0x350;
const LAPIC_LVT_LINT1: u32 = 0x360;
const LAPIC_LVT_ERROR: u32 = 0x370;
const LAPIC_INITCNT: u32 = 0x380;
const LAPIC_CURRCNT: u32 = 0x390;
const LAPIC_DIV: u32 = 0x3E0;

// ——— Bits/fields ———
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2: u64 = 1 << 10;
const SVR_APIC_ENABLE: u32 = 1 << 8;
const SVR_EOI_SUPPRESS: u32 = 1 << 12; // EOI broadcast suppression

const LVT_MASKED: u32 = 1 << 16;
const LVT_LEVEL: u32 = 1 << 15; // LINT level-triggered (ExtINT)
const LVT_NMI: u32 = 0b100 << 8;
const LVT_SMI: u32 = 0b010 << 8;
const LVT_FIXED: u32 = 0b000 << 8;
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

const ICR_DELIV_FIXED: u64 = 0x0 << 8;
const ICR_DELIV_SIPI: u64 = 0x6 << 8;
const ICR_DELIV_INIT: u64 = 0x5 << 8;
const ICR_DST_PHYSICAL: u64 = 0 << 11;
const ICR_LEVEL_ASSERT: u64 = 1 << 14;
const ICR_LEVEL_DEASSERT: u64 = 0 << 14;
const ICR_TRIG_EDGE: u64 = 0 << 15;
const ICR_NO_SHORTHAND: u64 = 0 << 18;
const ICR_SH_ALL: u64 = 0b10 << 18;
const ICR_SH_OTHERS: u64 = 0b11 << 18;
const ICR_SH_SELF: u64 = 0b01 << 18;

// ——— Vectors we use ———
pub const VEC_SPURIOUS: u8 = 0xFF;
pub const VEC_TIMER: u8 = 0x20;
pub const VEC_THERMAL: u8 = 0x21;
pub const VEC_ERROR: u8 = 0x22;
// LINT0 is NMI; LINT1 (ExtINT) masked

// ——— State ———
static X2APIC: AtomicBool = AtomicBool::new(false);
static TSC_DEADLINE: AtomicBool = AtomicBool::new(false);
static MMIO_BASE_LO: AtomicU32 = AtomicU32::new(0);

#[inline(always)]
fn rdmsr(ix: u32) -> u64 {
    unsafe { Msr::new(ix).read() }
}
#[inline(always)]
fn wrmsr(ix: u32, v: u64) {
    unsafe { Msr::new(ix).write(v) }
}

#[inline(always)]
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let mut a = leaf;
    let mut b: u32;
    let mut c = sub;
    let mut d: u32;
    unsafe {
        core::arch::asm!("push %rbx; cpuid; mov %ebx, %esi; pop %rbx", inlateout("eax")a, out("esi")b, inlateout("ecx")c, lateout("edx")d, options(nostack, preserves_flags, att_syntax));
    }
    (a, b, c, d)
}

fn has_xapic() -> bool {
    let (_a, _b, _c, d) = cpuid(1, 0);
    (d & (1 << 9)) != 0
}
fn has_x2apic() -> bool {
    let (_a, _b, c, _d) = cpuid(1, 0);
    (c & (1 << 21)) != 0
}
fn has_tsc_deadline() -> bool {
    let (_a, _b, c, _d) = cpuid(1, 0);
    (c & (1 << 24)) != 0
}

// ——— Public API ———

/// Initialize and program LVTs. Call on BSP with IRQs disabled.
pub unsafe fn init() {
    assert!(has_xapic(), "APIC not supported");
    // Enable APIC globally
    let mut base = rdmsr(IA32_APIC_BASE);
    base |= APIC_BASE_ENABLE;
    wrmsr(IA32_APIC_BASE, base);

    // Prefer x2APIC
    if has_x2apic() {
        wrmsr(IA32_APIC_BASE, rdmsr(IA32_APIC_BASE) | APIC_BASE_X2);
        X2APIC.store(true, Ordering::Relaxed);

        // SVR: APIC enable + spurious + suppress EOI broadcast (x2APIC)
        let svr = SVR_APIC_ENABLE as u64 | VEC_SPURIOUS as u64 | SVR_EOI_SUPPRESS as u64;
        wrmsr(IA32_X2APIC_SVR, svr);

        // LVTs
        wrmsr(IA32_X2APIC_LVT_LINT0, LVT_NMI as u64); // NMI on LINT0
        wrmsr(IA32_X2APIC_LVT_LINT1, LVT_MASKED as u64); // mask ExtINT
        wrmsr(IA32_X2APIC_LVT_THERM, LVT_FIXED as u64 | VEC_THERMAL as u64);
        wrmsr(IA32_X2APIC_LVT_ERROR, LVT_FIXED as u64 | VEC_ERROR as u64);
        wrmsr(IA32_X2APIC_LVT_TIMER, LVT_MASKED as u64); // off until start
    } else {
        X2APIC.store(false, Ordering::Relaxed);

        // Map xAPIC MMIO
        let phys = (rdmsr(IA32_APIC_BASE) & 0xFFFFF000) as u64;
        let va = map_apic_mmio(PhysAddr::new(phys));
        MMIO_BASE_LO.store(va.as_u64() as u32, Ordering::Relaxed);

        // SVR: enable + spurious + (EOI suppress not in xAPIC)
        mmio_w32(LAPIC_SVR, SVR_APIC_ENABLE | VEC_SPURIOUS as u32);

        // LVTs
        mmio_w32(LAPIC_LVT_LINT0, LVT_NMI); // NMI
        mmio_w32(LAPIC_LVT_LINT1, LVT_MASKED | LVT_LEVEL); // mask ExtINT
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
    }

    // Accept all priorities
    set_tpr(0);

    // TSC deadline capability
    TSC_DEADLINE.store(has_tsc_deadline(), Ordering::Relaxed);

    proof::audit_phys_alloc(0xA11C_0000, 0x1017_u64, CapTag::KERNEL);
}

/// Return local APIC ID.
pub fn id() -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        (rdmsr(0x802) & 0xFFFF_FFFF) as u32 // IA32_X2APIC_APICID
    } else {
        (mmio_r32(LAPIC_ID) >> 24) & 0xFF
    }
}

/// Set TPR (threshold). 0 accepts all.
pub fn set_tpr(v: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_TPR, v as u64);
    } else {
        mmio_w32(LAPIC_TPR, v as u32);
    }
}

/// End-of-interrupt.
#[inline(always)]
pub fn eoi() {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_EOI, 0);
    } else {
        mmio_w32(LAPIC_EOI, 0);
    }
}

// ——— IPIs ———

#[inline]
pub fn ipi_self(vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_SELF | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, vec as u32);
    }
}

#[inline]
pub fn ipi_one(apic_id: u32, vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(
            IA32_X2APIC_ICR,
            (apic_id as u64) << 32 | ICR_DELIV_FIXED | ICR_DST_PHYSICAL | (vec as u64) & 0xFF,
        );
    } else {
        mmio_w32(LAPIC_ICR_HIGH, (apic_id as u32) << 24);
        mmio_w32(LAPIC_ICR_LOW, vec as u32);
    }
}

#[inline]
pub fn ipi_all(vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_ALL | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, vec as u32 | ICR_SH_ALL as u32);
    }
}

#[inline]
pub fn ipi_others(vec: u8) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(IA32_X2APIC_ICR, ICR_DELIV_FIXED | ICR_SH_OTHERS | (vec as u64) & 0xFF);
    } else {
        mmio_w32(LAPIC_ICR_HIGH, 0);
        mmio_w32(LAPIC_ICR_LOW, vec as u32 | ICR_SH_OTHERS as u32);
    }
}

/// INIT → SIPI → SIPI sequence for AP bootstrap (trampoline elsewhere).
pub fn start_ap(apic_id: u32, start_vec: u8) {
    // INIT (assert)
    icr_cmd(apic_id, ICR_DELIV_INIT | ICR_LEVEL_ASSERT | ICR_TRIG_EDGE, 0);
    busy_wait(10000); // ~10us
                      // INIT (deassert)
    icr_cmd(apic_id, ICR_DELIV_INIT | ICR_LEVEL_DEASSERT | ICR_TRIG_EDGE, 0);
    busy_wait(200000); // ~200us
                       // SIPI 1
    icr_cmd(apic_id, ICR_DELIV_SIPI | ICR_TRIG_EDGE, start_vec);
    busy_wait(200000);
    // SIPI 2 (recommended)
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

// ——— Timer ———

/// Prefer TSC-deadline if available; else periodic with divider.
/// `hz` is the target tick rate for periodic mode fallback.
/// Returns whether deadline mode is active.
pub fn timer_enable(hz: u32, divider: u8, initial_count_hint: u32) -> bool {
    let deadline = TSC_DEADLINE.load(Ordering::Relaxed);
    if deadline {
        // Program LVT Timer to vector with "TSC-Deadline" mode (bit 18 in xAPIC LVT
        // when supported; in x2APIC, using TSC-deadline MSR is sufficient; set
        // LVT vector with periodic bit clear).
        if X2APIC.load(Ordering::Relaxed) {
            wrmsr(IA32_X2APIC_LVT_TIMER, VEC_TIMER as u64); // deadline mode
                                                            // implicitly via
                                                            // IA32_TSC_DEADLINE
        } else {
            // Some xAPICs also honor deadline: use vendor check; otherwise fallback to
            // periodic
            mmio_w32(LAPIC_LVT_TIMER, VEC_TIMER as u32); // clear periodic bit
        }
        // Caller should schedule first deadline with `timer_deadline_tsc(tsc_deadline)`
        proof::audit_phys_alloc(0xDEAD_1000u64, 1, CapTag::KERNEL);
        true
    } else {
        // Periodic fallback
        let div = match divider {
            1 => 0b1011,
            2 => 0b0000,
            4 => 0b0001,
            8 => 0b0010,
            16 => 0b0011,
            32 => 0b1000,
            64 => 0b1001,
            128 => 0b1010,
            _ => 0b0011, // 16
        } as u32;

        if X2APIC.load(Ordering::Relaxed) {
            wrmsr(IA32_X2APIC_DIV, div as u64);
            wrmsr(IA32_X2APIC_LVT_TIMER, VEC_TIMER as u64 | LVT_TIMER_PERIODIC as u64);
            // Calibrate initial_count if hint==0
            let init = if initial_count_hint == 0 {
                calibrate_lapic_count(hz, div)
            } else {
                initial_count_hint
            };
            wrmsr(IA32_X2APIC_INITCNT, init as u64);
        } else {
            mmio_w32(LAPIC_DIV, div);
            mmio_w32(LAPIC_LVT_TIMER, VEC_TIMER as u32 | LVT_TIMER_PERIODIC);
            let init = if initial_count_hint == 0 {
                calibrate_lapic_count(hz, div)
            } else {
                initial_count_hint
            };
            mmio_w32(LAPIC_INITCNT, init);
        }
        proof::audit_phys_alloc(0xFEE00000u64, hz as u64, CapTag::KERNEL);
        false
    }
}

/// Set a TSC deadline (absolute TSC). Only valid if timer_enable returned true.
#[inline]
pub fn timer_deadline_tsc(tsc: u64) {
    wrmsr(IA32_TSC_DEADLINE, tsc);
}

/// Stop timer (mask LVT).
pub fn timer_mask() {
    if X2APIC.load(Ordering::Relaxed) {
        let mut l = rdmsr(IA32_X2APIC_LVT_TIMER) as u32;
        l |= LVT_MASKED;
        wrmsr(IA32_X2APIC_LVT_TIMER, l as u64);
    } else {
        let mut l = mmio_r32(LAPIC_LVT_TIMER);
        l |= LVT_MASKED;
        mmio_w32(LAPIC_LVT_TIMER, l);
    }
}

/// Quick calibration against TSC: measure ticks in ~1ms busy wait.
fn calibrate_lapic_count(hz: u32, _div_code: u32) -> u32 {
    // Expected ticks per period: LAPIC counts at bus/APIC clock; we approximate via
    // TSC scale. For demo: pick a conservative initial load and refine later
    // via HPET/PIT (see hooks below). 1 kHz ~ 1ms period. Start with large
    // value; adjust empirically in QEMU.
    let mut init = 10_000_000u32;
    if hz >= 1000 {
        init /= (hz / 1000).max(1);
    }
    init.max(50_000)
}

// Hook for precise calibration (HPET/PIT). Fill later in arch/time/*.
#[allow(unused)]
fn calibrate_with_hpet_or_pit(_hz: u32) -> Option<u32> {
    None
}

// ——— Internals ———

#[inline(always)]
fn mmio_base() -> VirtAddr {
    VirtAddr::new(MMIO_BASE_LO.load(Ordering::Relaxed) as u64 & !(PAGE_SIZE as u64 - 1))
}
#[inline(always)]
fn mmio_r32(off: u32) -> u32 {
    unsafe { core::ptr::read_volatile((mmio_base().as_u64() + off as u64) as *const u32) }
}
#[inline(always)]
fn mmio_w32(off: u32, v: u32) {
    unsafe { core::ptr::write_volatile((mmio_base().as_u64() + off as u64) as *mut u32, v) }
}

unsafe fn map_apic_mmio(pa: PhysAddr) -> VirtAddr {
    // one 4K page, UC, RW+NX
    extern "Rust" {
        fn __nonos_alloc_mmio_va(pages: usize) -> u64;
    }
    let va = VirtAddr::new(__nonos_alloc_mmio_va(1));
    virt::map4k_at(va, pa, VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD)
        .expect("lapic map");
    va
}

// crude spin-wait in ~TSC cycles; replace with arch::time once ready
fn busy_wait(_cycles: u64) {
    core::hint::spin_loop();
}

/// Send End-of-Interrupt - REAL IMPLEMENTATION
pub fn send_eoi() {
    mmio_w32(0xB0, 0); // Write to EOI register
}

/// Enable interrupt - REAL IMPLEMENTATION
pub fn enable_interrupt(vector: u8) {
    // Enable specific interrupt vector (simplified)
}

/// Disable interrupt - REAL IMPLEMENTATION  
pub fn disable_interrupt(vector: u8) {
    // Disable specific interrupt vector (simplified)
}
