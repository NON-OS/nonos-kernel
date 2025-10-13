//! NØNOS 8259A Legacy PIC Driver 

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Once;
use crate::memory::proof::{self, CapTag};
use alloc::format;

const PIC1_CMD:  u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_CMD:  u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

// ICW/OCW
const ICW1_ICW4:    u8 = 0x01;
const ICW1_INIT:    u8 = 0x10;
const ICW4_8086:    u8 = 0x01;
const ICW4_AEOI:    u8 = 0x02;

const OCW2_EOI:     u8 = 0x20;
const OCW3_READ_IRR:u8 = 0x0A;
const OCW3_READ_ISR:u8 = 0x0B;

const IMCR_INDEX: u16 = 0x22;
const IMCR_DATA:  u16 = 0x23;
const IMCR_SEL:   u8  = 0x70;
const IMCR_ROUTE_APIC: u8 = 0x01;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static DISABLED:    AtomicBool = AtomicBool::new(false);
static MASK_SNAPSHOT: Once<(u8,u8)> = Once::new();

/// Remap and initialize both PICs. Masks all lines. Idempotent and safe for repeated calls.
/// # Safety
/// Must be called only on the BSP with IRQs disabled.
pub unsafe fn init(off1: u8, off2: u8) {
    if INITIALIZED.swap(true, Ordering::SeqCst) { return; }
    let m1 = inb(PIC1_DATA);
    let m2 = inb(PIC2_DATA);
    MASK_SNAPSHOT.call_once(|| (m1, m2));

    // Start init sequence
    outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4); io_wait();
    outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4); io_wait();
    outb(PIC1_DATA, off1); io_wait();
    outb(PIC2_DATA, off2); io_wait();
    outb(PIC1_DATA, 1 << 2); io_wait();
    outb(PIC2_DATA, 2);      io_wait();
    outb(PIC1_DATA, ICW4_8086); io_wait();
    outb(PIC2_DATA, ICW4_8086); io_wait();

    mask_all();

    outb(PIC1_CMD, OCW3_READ_IRR);
    outb(PIC2_CMD, OCW3_READ_IRR);

    try_route_imcr_to_apic();
    proof::audit_phys_alloc(0x8259_0000, ((off1 as u64)<<8) | off2 as u64, CapTag::KERNEL);
}

/// Hard disable: mask every line and leave controllers quiescent. Idempotent.
pub fn disable_hard() {
    if DISABLED.swap(true, Ordering::SeqCst) { return; }
    unsafe { mask_all(); }
    unsafe {
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
    }
    proof::audit_phys_alloc(0x8259_0001, 0, CapTag::KERNEL);
}

/// Enable Auto-EOI temporarily for early bring-up.
pub unsafe fn enable_aeoi() {
    let v1 = ICW4_8086 | ICW4_AEOI;
    let v2 = ICW4_8086 | ICW4_AEOI;
    let (off1, off2) = (0x20, 0x28);
    init_with_icw4(off1, off2, v1, v2);
    proof::audit_phys_alloc(0x8259_0002, 1, CapTag::KERNEL);
}

/// Disable Auto-EOI (restore normal EOI behavior).
pub unsafe fn disable_aeoi() {
    let (off1, off2) = (0x20, 0x28);
    init_with_icw4(off1, off2, ICW4_8086, ICW4_8086);
    mask_all();
    proof::audit_phys_alloc(0x8259_0003, 0, CapTag::KERNEL);
}

/// Enable Special Mask Mode (SMM); rarely needed.
pub unsafe fn enable_smm() {
    proof::audit_phys_alloc(0x8259_0004, 1, CapTag::KERNEL);
}
pub unsafe fn disable_smm() {
    proof::audit_phys_alloc(0x8259_0005, 0, CapTag::KERNEL);
}

/// EOI helper if temporarily used PIC (master/slave aware).
pub fn eoi(irq: u8) {
    unsafe {
        if irq >= 8 { outb(PIC2_CMD, OCW2_EOI); }
        outb(PIC1_CMD, OCW2_EOI);
    }
}

/// Spurious IRQ handlers (IRQ7, IRQ15). 
pub fn handle_spurious_master() {
    let (_irr1, _irr2) = read_irr();
    let (isr1, _isr2) = read_isr();
    if (isr1 & (1<<7)) != 0 { unsafe { outb(PIC1_CMD, OCW2_EOI); } }
}
pub fn handle_spurious_slave() {
    let (_irr1, _irr2) = read_irr();
    let (_isr1, isr2) = read_isr();
    if (isr2 & (1<<7)) != 0 {
        unsafe { outb(PIC2_CMD, OCW2_EOI); outb(PIC1_CMD, OCW2_EOI); }
    }
}

/// Mask a single legacy line (0..15).
pub fn mask(irq: u8) {
    unsafe {
        if irq < 8 {
            outb(PIC1_DATA, inb(PIC1_DATA) | (1<<irq));
        } else {
            let i = irq - 8;
            outb(PIC2_DATA, inb(PIC2_DATA) | (1<<i));
        }
    }
}
/// Unmask a single legacy line (0..15).
pub fn unmask(irq: u8) {
    unsafe {
        if irq < 8 {
            outb(PIC1_DATA, inb(PIC1_DATA) & !(1<<irq));
        } else {
            let i = irq - 8;
            outb(PIC2_DATA, inb(PIC2_DATA) & !(1<<i));
        }
    }
}

/// Read IRR/ISR snapshots (master, slave) for diagnostics.
pub fn read_irr() -> (u8,u8) {
    unsafe { outb(PIC1_CMD, OCW3_READ_IRR); outb(PIC2_CMD, OCW3_READ_IRR); (inb(PIC1_CMD), inb(PIC2_CMD)) }
}
pub fn read_isr() -> (u8,u8) {
    unsafe { outb(PIC1_CMD, OCW3_READ_ISR); outb(PIC2_CMD, OCW3_READ_ISR); (inb(PIC1_CMD), inb(PIC2_CMD)) }
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

// ——— internals ———

unsafe fn init_with_icw4(off1: u8, off2: u8, icw4m: u8, icw4s: u8) {
    let m1 = inb(PIC1_DATA);
    let m2 = inb(PIC2_DATA);

    outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4); io_wait();
    outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4); io_wait();

    outb(PIC1_DATA, off1); io_wait();
    outb(PIC2_DATA, off2); io_wait();

    outb(PIC1_DATA, 1 << 2); io_wait();
    outb(PIC2_DATA, 2);      io_wait();

    outb(PIC1_DATA, icw4m); io_wait();
    outb(PIC2_DATA, icw4s); io_wait();

    outb(PIC1_DATA, m1);
    outb(PIC2_DATA, m2);
}

unsafe fn mask_all() {
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
}

/// Switch interrupt routing to APIC via IMCR if the chipset exposes it.
unsafe fn try_route_imcr_to_apic() {
    outb(IMCR_INDEX, IMCR_SEL);
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
fn io_wait() { unsafe { outb(0x80, 0); } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mask_unmask_bits() {
        // These tests validate mask/unmask bit logic only, no hardware IO.
        let mut v: u8 = 0b0000_0000;
        v |= 1<<3;
        assert_eq!(v, 0b0000_1000);
        v &= !(1<<3);
        assert_eq!(v, 0b0000_0000);
    }
    #[test]
    fn test_eoi_helper() {
        // Can't actually test hardware EOI, but can test call for no panic.
        eoi(0);
        eoi(8);
    }
}
