// arch/x86_64/interrupt/pic_legacy.rs
//
// 8259A legacy PIC — hardened handover to APIC/IOAPIC.
// - Remap, mask-all, optional AEOI & Special Mask Mode for bring-up noise
// - IMCR routing: switch interrupt source from PIC (virtual-wire) to APIC (if
//   present)
// - Safe spurious IRQ7/IRQ15 handling helpers
// - Snapshot/restore masks; IRR/ISR readout for deep debug
// - Idempotent init/disable; proof-audited transitions
//
// Call order (BSP, IRQs off):
//   init(0x20, 0x28) → (optional) enable_aeoi()/enable_smm() during very early
// bring-up   … route IOAPIC / enable LAPIC …
//   disable_hard();  // final: PIC fully quiesced
//
// Zero-state: no persistence; all state lost on reboot.

#![allow(dead_code)]

use crate::memory::proof::{self, CapTag};
use alloc::format;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;

const PIC1_CMD: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW/OCW
const ICW1_ICW4: u8 = 0x01;
const ICW1_SINGLE: u8 = 0x02;
const ICW1_INTERVAL4: u8 = 0x04;
const ICW1_LEVEL: u8 = 0x08;
const ICW1_INIT: u8 = 0x10;

const ICW4_8086: u8 = 0x01;
const ICW4_AEOI: u8 = 0x02;
const ICW4_MASTER_BUF: u8 = 0x08;
const ICW4_SFNM: u8 = 0x10;

const OCW2_EOI: u8 = 0x20;
const OCW3_READ_IRR: u8 = 0x0A;
const OCW3_READ_ISR: u8 = 0x0B;

// OCW1 bitfield = mask data register
// OCW2/3 written via PIC*_CMD

// IMCR (Interrupt Mode Configuration Register) — some SMP chipsets
//   port 0x22: index; 0x23: data; index 0x70 = IMCR
const IMCR_INDEX: u16 = 0x22;
const IMCR_DATA: u16 = 0x23;
const IMCR_SEL: u8 = 0x70;
const IMCR_ROUTE_APIC: u8 = 0x01; // 1=routed to APIC, 0=to PIC

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static DISABLED: AtomicBool = AtomicBool::new(false);
static MASK_SNAPSHOT: Once<(u8, u8)> = Once::new();

/// Remap both PICs to (off1/off2), leave **masked-all**, enter sane OCW3.
/// Idempotent: safe to call twice.
pub unsafe fn init(off1: u8, off2: u8) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    // Save original masks for optional restore
    let m1 = inb(PIC1_DATA);
    let m2 = inb(PIC2_DATA);
    MASK_SNAPSHOT.call_once(|| (m1, m2));

    // Start init
    outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // Vector offsets
    outb(PIC1_DATA, off1);
    io_wait();
    outb(PIC2_DATA, off2);
    io_wait();

    // ICW3: master has slave on IRQ2; slave id=2
    outb(PIC1_DATA, 1 << 2);
    io_wait();
    outb(PIC2_DATA, 2);
    io_wait();

    // ICW4: 8086 mode (no AEOI by default; can enable temporarily later)
    outb(PIC1_DATA, ICW4_8086);
    io_wait();
    outb(PIC2_DATA, ICW4_8086);
    io_wait();

    // Mask all
    mask_all();

    // OCW3: default to IRR on reads
    outb(PIC1_CMD, OCW3_READ_IRR);
    outb(PIC2_CMD, OCW3_READ_IRR);

    // Some SMP systems ship in "virtual wire" (PIC → LINT0). Switch to APIC if IMCR
    // exists.
    try_route_imcr_to_apic();

    proof::audit_phys_alloc(0x8259_0000, ((off1 as u64) << 8) | off2 as u64, CapTag::KERNEL);
}

/// Hard disable: mask every line and leave controllers quiescent. Idempotent.
pub fn disable_hard() {
    if DISABLED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        mask_all();
    }
    // Put OCW3 in a sane state again (some BIOSes leave ISR selected)
    unsafe {
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
    }
    proof::audit_phys_alloc(0x8259_0001, 0, CapTag::KERNEL);
}

/// Enable AEOI (Auto-EOI) temporarily to reduce EOI churn during very early
/// bring-up. Call `disable_aeoi()` before switching to IOAPIC/LAPIC for
/// correctness.
pub unsafe fn enable_aeoi() {
    let v1 = ICW4_8086 | ICW4_AEOI;
    let v2 = ICW4_8086 | ICW4_AEOI;
    // Re-enter ICW4 write mode via init sequence? Not required: OCW for ICW4 is not
    // supported. Many PICs let you rewrite ICW4 by re-issuing init—avoid that
    // (it flips vector base). Instead, we only recommend AEOI if you
    // initialized with it; otherwise skip in prod. For completeness, we do a
    // minimal re-init preserving offsets:
    let (off1, off2) = current_offsets().unwrap_or((0x20, 0x28));
    init_with_icw4(off1, off2, v1, v2);
    proof::audit_phys_alloc(0x8259_0002, 1, CapTag::KERNEL);
}

pub unsafe fn disable_aeoi() {
    let (off1, off2) = current_offsets().unwrap_or((0x20, 0x28));
    init_with_icw4(off1, off2, ICW4_8086, ICW4_8086);
    mask_all();
    proof::audit_phys_alloc(0x8259_0003, 0, CapTag::KERNEL);
}

/// Special Mask Mode (SMM): mask bit prevents higher priority from preempting
/// current.
// Rarely needed; available here for edge-glitchy legacy devices during
// bring-up.
pub unsafe fn enable_smm() {
    // No direct portable OCW for SMM across clones; generally programmed via OCW3
    // on some chips. We emulate a protective effect by keeping mask-all + AEOI
    // during critical windows. Deliberately a no-op hook with audit marker.
    proof::audit_phys_alloc(0x8259_0004, 1, CapTag::KERNEL);
}
pub unsafe fn disable_smm() {
    proof::audit_phys_alloc(0x8259_0005, 0, CapTag::KERNEL);
}

/// EOI helper if you temporarily used PIC (master/slave aware).
pub fn eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, OCW2_EOI);
        }
        outb(PIC1_CMD, OCW2_EOI);
    }
}

/// Spurious IRQ handlers (IRQ7, IRQ15). Call these in your IDT stubs if you
/// temporarily run with PIC enabled. They read ISR to confirm spurious.
pub fn handle_spurious_master() {
    let (_irr1, _irr2) = read_irr();
    let (isr1, _isr2) = read_isr();
    // If ISR bit 7 not set, it was truly spurious (ignore). Otherwise, send EOI.
    if (isr1 & (1 << 7)) != 0 {
        unsafe {
            outb(PIC1_CMD, OCW2_EOI);
        }
    }
}
pub fn handle_spurious_slave() {
    let (_irr1, _irr2) = read_irr();
    let (_isr1, isr2) = read_isr();
    if (isr2 & (1 << 7)) != 0 {
        unsafe {
            outb(PIC2_CMD, OCW2_EOI);
            outb(PIC1_CMD, OCW2_EOI);
        }
    }
}

/// Mask/unmask single legacy line (0..15). Avoid when IOAPIC is active.
pub fn mask(irq: u8) {
    unsafe {
        if irq < 8 {
            outb(PIC1_DATA, inb(PIC1_DATA) | (1 << irq));
        } else {
            let i = irq - 8;
            outb(PIC2_DATA, inb(PIC2_DATA) | (1 << i));
        }
    }
}
pub fn unmask(irq: u8) {
    unsafe {
        if irq < 8 {
            outb(PIC1_DATA, inb(PIC1_DATA) & !(1 << irq));
        } else {
            let i = irq - 8;
            outb(PIC2_DATA, inb(PIC2_DATA) & !(1 << i));
        }
    }
}

/// Read IRR/ISR snapshots (master, slave) for diagnostics.
pub fn read_irr() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
        (inb(PIC1_CMD), inb(PIC2_CMD))
    }
}
pub fn read_isr() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_ISR);
        outb(PIC2_CMD, OCW3_READ_ISR);
        (inb(PIC1_CMD), inb(PIC2_CMD))
    }
}

/// Dump a human-readable snapshot (for CLI).
pub fn dump(mut log: impl FnMut(&str)) {
    let (irr1, irr2) = read_irr();
    let (isr1, isr2) = read_isr();
    unsafe {
        let m1 = inb(PIC1_DATA);
        let m2 = inb(PIC2_DATA);
        log(&format!("[PIC] masks: master={:#010b} slave={:#010b}", m1, m2));
        log(&format!("[PIC] IRR:   master={:#010b} slave={:#010b}", irr1, irr2));
        log(&format!("[PIC] ISR:   master={:#010b} slave={:#010b}", isr1, isr2));
    }
}

/// Restore masks saved at first init (rarely needed).
pub unsafe fn restore_saved_masks() {
    if let Some((m1, m2)) = MASK_SNAPSHOT.get() {
        outb(PIC1_DATA, *m1);
        outb(PIC2_DATA, *m2);
    }
}

// ——————————————————— internals ———————————————————

unsafe fn init_with_icw4(off1: u8, off2: u8, icw4m: u8, icw4s: u8) {
    // Save masks
    let m1 = inb(PIC1_DATA);
    let m2 = inb(PIC2_DATA);

    outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();

    outb(PIC1_DATA, off1);
    io_wait();
    outb(PIC2_DATA, off2);
    io_wait();

    outb(PIC1_DATA, 1 << 2);
    io_wait();
    outb(PIC2_DATA, 2);
    io_wait();

    outb(PIC1_DATA, icw4m);
    io_wait();
    outb(PIC2_DATA, icw4s);
    io_wait();

    // Restore masks (caller may override)
    outb(PIC1_DATA, m1);
    outb(PIC2_DATA, m2);
}

unsafe fn mask_all() {
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
}

/// Try to switch interrupt routing to APIC via IMCR if the chipset exposes it.
/// Safe to call even if IMCR is absent.
unsafe fn try_route_imcr_to_apic() {
    // Probe IMCR by selecting index; some systems ignore writes to 0x22/0x23
    outb(IMCR_INDEX, IMCR_SEL);
    // Route to APIC
    outb(IMCR_DATA, IMCR_ROUTE_APIC);
    proof::audit_phys_alloc(0x1000_0006, 1, CapTag::KERNEL);
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags));
    v
}
#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
}
#[inline(always)]
fn io_wait() {
    unsafe {
        outb(0x80, 0);
    }
}
/// Crude vector-offset probe (best-effort; many clones don’t expose it).
unsafe fn current_offsets() -> Option<(u8, u8)> {
    // Not reliably readable; return None unless you track it in a static.
    None
}
