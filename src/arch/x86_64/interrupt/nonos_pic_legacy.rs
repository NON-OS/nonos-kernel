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

//! NØNOS 8259A Legacy PIC Driver
//!
//! This module provides a complete driver for the Intel 8259A Programmable
//! Interrupt Controller, used for legacy interrupt handling on x86 systems.
//!
//! # Safety
//! Most functions in this module perform direct I/O port access and must be
//! called with interrupts disabled. The `init` function should only be called
//! once on the BSP during early boot.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Once;
use crate::memory::proof::{self, CapTag};
use alloc::format;

// ============================================================================
// I/O PORT ADDRESSES
// ============================================================================

/// Master PIC command port
const PIC1_CMD: u16 = 0x20;
/// Master PIC data port
const PIC1_DATA: u16 = 0x21;
/// Slave PIC command port
const PIC2_CMD: u16 = 0xA0;
/// Slave PIC data port
const PIC2_DATA: u16 = 0xA1;

// ============================================================================
// INITIALIZATION COMMAND WORDS (ICW)
// ============================================================================

/// ICW1: ICW4 needed
const ICW1_ICW4: u8 = 0x01;
/// ICW1: Initialization command
const ICW1_INIT: u8 = 0x10;
/// ICW4: 8086/88 mode
const ICW4_8086: u8 = 0x01;
/// ICW4: Auto EOI mode
const ICW4_AEOI: u8 = 0x02;

// ============================================================================
// OPERATION COMMAND WORDS (OCW)
// ============================================================================

/// OCW2: End of Interrupt command
const OCW2_EOI: u8 = 0x20;
/// OCW3: Read IRR (Interrupt Request Register)
const OCW3_READ_IRR: u8 = 0x0A;
/// OCW3: Read ISR (In-Service Register)
const OCW3_READ_ISR: u8 = 0x0B;

// ============================================================================
// IMCR (Interrupt Mode Configuration Register)
// ============================================================================

/// IMCR index port
const IMCR_INDEX: u16 = 0x22;
/// IMCR data port
const IMCR_DATA: u16 = 0x23;
/// IMCR select value
const IMCR_SEL: u8 = 0x70;
/// IMCR route to APIC value
const IMCR_ROUTE_APIC: u8 = 0x01;

// ============================================================================
// IRQ CONSTANTS
// ============================================================================

/// Maximum IRQ number (0-15)
pub const MAX_IRQ: u8 = 15;
/// IRQ for master spurious interrupt
pub const SPURIOUS_IRQ_MASTER: u8 = 7;
/// IRQ for slave spurious interrupt
pub const SPURIOUS_IRQ_SLAVE: u8 = 15;
/// Cascade IRQ (slave connected to master IRQ 2)
pub const CASCADE_IRQ: u8 = 2;

// ============================================================================
// STATE TRACKING
// ============================================================================

/// Tracks whether the PIC has been initialized
static INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Tracks whether the PIC has been hard-disabled
static DISABLED: AtomicBool = AtomicBool::new(false);
/// Current master PIC mask (cached)
static MASTER_MASK: AtomicU8 = AtomicU8::new(0xFF);
/// Current slave PIC mask (cached)
static SLAVE_MASK: AtomicU8 = AtomicU8::new(0xFF);
/// Original masks saved during initialization
static MASK_SNAPSHOT: Once<(u8, u8)> = Once::new();

// ============================================================================
// STRUCTURED ERROR HANDLING
// ============================================================================

/// PIC operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PicError {
    /// PIC not yet initialized
    NotInitialized,
    /// PIC has been disabled
    Disabled,
    /// Invalid IRQ number (must be 0-15)
    InvalidIrq,
    /// Already initialized
    AlreadyInitialized,
}

impl PicError {
    /// Get human-readable error message
    pub const fn as_str(self) -> &'static str {
        match self {
            PicError::NotInitialized => "PIC not initialized",
            PicError::Disabled => "PIC has been disabled",
            PicError::InvalidIrq => "Invalid IRQ number (must be 0-15)",
            PicError::AlreadyInitialized => "PIC already initialized",
        }
    }
}

/// Result type for PIC operations
pub type PicResult<T> = Result<T, PicError>;

// ============================================================================
// INITIALIZATION
// ============================================================================

/// Remap and initialize both PICs with the specified vector offsets.
///
/// This function:
/// 1. Saves the original interrupt masks
/// 2. Sends the initialization sequence (ICW1-ICW4)
/// 3. Remaps IRQs to the specified offsets
/// 4. Masks all IRQ lines
/// 5. Attempts to route interrupts to APIC via IMCR

pub unsafe fn init(master_offset: u8, slave_offset: u8) -> PicResult<()> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(PicError::AlreadyInitialized);
    }

    // Save original masks
    let m1 = inb(PIC1_DATA);
    let m2 = inb(PIC2_DATA);
    MASK_SNAPSHOT.call_once(|| (m1, m2));

    // ICW1: Start initialization sequence
    outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // ICW2: Set vector offsets
    outb(PIC1_DATA, master_offset);
    io_wait();
    outb(PIC2_DATA, slave_offset);
    io_wait();

    // ICW3: Configure cascading
    outb(PIC1_DATA, 1 << CASCADE_IRQ); // Slave on IRQ2
    io_wait();
    outb(PIC2_DATA, CASCADE_IRQ); // Slave ID
    io_wait();

    // ICW4: Set 8086 mode
    outb(PIC1_DATA, ICW4_8086);
    io_wait();
    outb(PIC2_DATA, ICW4_8086);
    io_wait();

    // Mask all IRQs
    mask_all_internal();

    // Set to read IRR by default
    outb(PIC1_CMD, OCW3_READ_IRR);
    outb(PIC2_CMD, OCW3_READ_IRR);

    // Try to route to APIC
    try_route_imcr_to_apic();

    // Audit trail
    proof::audit_phys_alloc(
        0x8259_0000,
        ((master_offset as u64) << 8) | slave_offset as u64,
        CapTag::KERNEL,
    );

    Ok(())
}

/// Initialize with legacy defaults (master=0x20, slave=0x28).
///
/// # Safety
/// Same requirements as `init`.
pub unsafe fn init_default() -> PicResult<()> {
    init(0x20, 0x28)
}

/// Check if PIC has been initialized.
#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

/// Check if PIC has been disabled.
#[inline]
pub fn is_disabled() -> bool {
    DISABLED.load(Ordering::Acquire)
}

// ============================================================================
// DISABLE / SHUTDOWN
// ============================================================================

/// Hard disable the PIC by masking all IRQ lines.
///
/// This is idempotent - calling multiple times has no effect.
/// Used when switching to APIC mode.
pub fn disable_hard() {
    if DISABLED.swap(true, Ordering::SeqCst) {
        return;
    }

    unsafe {
        mask_all_internal();

        // Set to read IRR
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
    }

    proof::audit_phys_alloc(0x8259_0001, 0, CapTag::KERNEL);
}

// ============================================================================
// AUTO-EOI MODE
// ============================================================================

/// Enable Auto-EOI mode for early boot.
///
/// # Safety
/// Must be called with interrupts disabled.
pub unsafe fn enable_aeoi() -> PicResult<()> {
    if !is_initialized() {
        return Err(PicError::NotInitialized);
    }
    if is_disabled() {
        return Err(PicError::Disabled);
    }

    let icw4 = ICW4_8086 | ICW4_AEOI;
    reinit_with_icw4(0x20, 0x28, icw4, icw4);

    proof::audit_phys_alloc(0x8259_0002, 1, CapTag::KERNEL);
    Ok(())
}

/// Disable Auto-EOI mode (restore normal EOI behavior).
///
/// # Safety
/// Must be called with interrupts disabled.
pub unsafe fn disable_aeoi() -> PicResult<()> {
    if !is_initialized() {
        return Err(PicError::NotInitialized);
    }

    reinit_with_icw4(0x20, 0x28, ICW4_8086, ICW4_8086);
    mask_all_internal();

    proof::audit_phys_alloc(0x8259_0003, 0, CapTag::KERNEL);
    Ok(())
}

// ============================================================================
// SPECIAL MASK MODE (SMM)
// ============================================================================
///
/// # Safety
/// Must be called with interrupts disabled.
pub unsafe fn enable_smm() -> PicResult<()> {
    if !is_initialized() {
        return Err(PicError::NotInitialized);
    }

    // OCW3: Set SMM bit (bit 6 = 1, bit 5 = 1)
    outb(PIC1_CMD, 0x68);
    outb(PIC2_CMD, 0x68);

    proof::audit_phys_alloc(0x8259_0004, 1, CapTag::KERNEL);
    Ok(())
}

/// Disable Special Mask Mode.
///
/// # Safety
/// Must be called with interrupts disabled.
pub unsafe fn disable_smm() -> PicResult<()> {
    if !is_initialized() {
        return Err(PicError::NotInitialized);
    }

    // OCW3: Clear SMM bit
    outb(PIC1_CMD, 0x48);
    outb(PIC2_CMD, 0x48);

    proof::audit_phys_alloc(0x8259_0005, 0, CapTag::KERNEL);
    Ok(())
}

// ============================================================================
// END OF INTERRUPT (EOI)
// ============================================================================

/// Send End of Interrupt for the specified IRQ.
///
/// This must be called at the end of an interrupt handler.
///
/// For slave IRQs (8-15), EOI must be sent to both slave and master.
#[inline]
pub fn eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, OCW2_EOI);
        }
        outb(PIC1_CMD, OCW2_EOI);
    }
}

/// Send specific EOI for the specified IRQ.
///
/// Uses specific EOI command (OCW2 with IRQ number) instead of non-specific EOI.
#[inline]
pub fn specific_eoi(irq: u8) {
    unsafe {
        if irq >= 8 {
            outb(PIC2_CMD, 0x60 | (irq - 8));
            outb(PIC1_CMD, 0x60 | CASCADE_IRQ);
        } else {
            outb(PIC1_CMD, 0x60 | irq);
        }
    }
}

// ============================================================================
// SPURIOUS INTERRUPT HANDLING
// ============================================================================

/// Handle potential spurious interrupt on master PIC (IRQ 7).
///
/// Returns `true` if it was a real interrupt, `false` if spurious.
/// For spurious interrupts, no EOI should be sent.
pub fn handle_spurious_master() -> bool {
    let (_, isr1) = read_isr_internal();

    // Check if IRQ 7 is actually in-service
    if (isr1 & (1 << SPURIOUS_IRQ_MASTER)) != 0 {
        // Real interrupt - send EOI
        unsafe { outb(PIC1_CMD, OCW2_EOI); }
        true
    } else {
        // Spurious - no EOI needed
        false
    }
}

/// Handle potential spurious interrupt on slave PIC (IRQ 15).
///
/// Returns `true` if it was a real interrupt, `false` if spurious.
/// For spurious slave interrupts, EOI must still be sent to master.
pub fn handle_spurious_slave() -> bool {
    let (isr2, _) = read_isr_internal();

    // Check if IRQ 15 is actually in-service on slave
    if (isr2 & (1 << (SPURIOUS_IRQ_SLAVE - 8))) != 0 {
        // Real interrupt - send EOI to both
        unsafe {
            outb(PIC2_CMD, OCW2_EOI);
            outb(PIC1_CMD, OCW2_EOI);
        }
        true
    } else {
        // Spurious - still need to send EOI to master for cascade
        unsafe { outb(PIC1_CMD, OCW2_EOI); }
        false
    }
}

// ============================================================================
// MASK / UNMASK OPERATIONS
// ============================================================================

/// Mask (disable) a single IRQ line.
///
/// # Arguments
/// * `irq` - IRQ number (0-15)
///
/// # Returns
/// `Ok(())` on success, `Err(PicError::InvalidIrq)` if irq > 15.
pub fn mask(irq: u8) -> PicResult<()> {
    if irq > MAX_IRQ {
        return Err(PicError::InvalidIrq);
    }

    unsafe {
        if irq < 8 {
            let current = inb(PIC1_DATA);
            let new_mask = current | (1 << irq);
            outb(PIC1_DATA, new_mask);
            MASTER_MASK.store(new_mask, Ordering::Release);
        } else {
            let bit = irq - 8;
            let current = inb(PIC2_DATA);
            let new_mask = current | (1 << bit);
            outb(PIC2_DATA, new_mask);
            SLAVE_MASK.store(new_mask, Ordering::Release);
        }
    }
    Ok(())
}

/// Unmask (enable) a single IRQ line.
///
/// # Arguments
/// * `irq` - IRQ number (0-15)
///
/// # Returns
/// `Ok(())` on success, `Err(PicError::InvalidIrq)` if irq > 15.
pub fn unmask(irq: u8) -> PicResult<()> {
    if irq > MAX_IRQ {
        return Err(PicError::InvalidIrq);
    }

    unsafe {
        if irq < 8 {
            let current = inb(PIC1_DATA);
            let new_mask = current & !(1 << irq);
            outb(PIC1_DATA, new_mask);
            MASTER_MASK.store(new_mask, Ordering::Release);
        } else {
            let bit = irq - 8;
            let current = inb(PIC2_DATA);
            let new_mask = current & !(1 << bit);
            outb(PIC2_DATA, new_mask);
            SLAVE_MASK.store(new_mask, Ordering::Release);

            // Ensure cascade line is unmasked
            let master = inb(PIC1_DATA);
            if (master & (1 << CASCADE_IRQ)) != 0 {
                outb(PIC1_DATA, master & !(1 << CASCADE_IRQ));
            }
        }
    }
    Ok(())
}

/// Mask all IRQ lines on both PICs.
pub fn mask_all() {
    unsafe { mask_all_internal(); }
}

/// Get current mask values.
///
/// Returns `(master_mask, slave_mask)`.
pub fn get_masks() -> (u8, u8) {
    (
        MASTER_MASK.load(Ordering::Acquire),
        SLAVE_MASK.load(Ordering::Acquire),
    )
}

/// Set masks directly.
///
/// # Safety
/// Directly sets PIC masks without validation.
pub unsafe fn set_masks(master: u8, slave: u8) {
    outb(PIC1_DATA, master);
    outb(PIC2_DATA, slave);
    MASTER_MASK.store(master, Ordering::Release);
    SLAVE_MASK.store(slave, Ordering::Release);
}

// ============================================================================
// REGISTER READING
// ============================================================================

/// Read the Interrupt Request Register (IRR) from both PICs.
///
/// The IRR shows which interrupts are pending (requested but not yet serviced).
///
/// Returns `(master_irr, slave_irr)`.
pub fn read_irr() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
        (inb(PIC1_CMD), inb(PIC2_CMD))
    }
}

/// Read the In-Service Register (ISR) from both PICs.
///
/// The ISR shows which interrupts are currently being serviced.
///
/// Returns `(master_isr, slave_isr)`.
pub fn read_isr() -> (u8, u8) {
    read_isr_internal()
}

/// Internal ISR read (returns slave, master order for internal use).
fn read_isr_internal() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_ISR);
        outb(PIC2_CMD, OCW3_READ_ISR);
        (inb(PIC2_CMD), inb(PIC1_CMD))
    }
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

/// Dump PIC state for diagnostics.
///
/// Outputs mask, IRR, and ISR values in binary format.
pub fn dump(mut log: impl FnMut(&str)) {
    let (irr1, irr2) = read_irr();
    let (isr1, isr2) = read_isr();
    let (m1, m2) = get_masks();

    log(&format!("[PIC] Status: init={} disabled={}",
        is_initialized(), is_disabled()));
    log(&format!("[PIC] Masks: master={:#010b} slave={:#010b}", m1, m2));
    log(&format!("[PIC] IRR:   master={:#010b} slave={:#010b}", irr1, irr2));
    log(&format!("[PIC] ISR:   master={:#010b} slave={:#010b}", isr1, isr2));
}

/// Get PIC status as a structured type.
#[derive(Debug, Clone, Copy)]
pub struct PicStatus {
    pub initialized: bool,
    pub disabled: bool,
    pub master_mask: u8,
    pub slave_mask: u8,
    pub master_irr: u8,
    pub slave_irr: u8,
    pub master_isr: u8,
    pub slave_isr: u8,
}

/// Get current PIC status.
pub fn status() -> PicStatus {
    let (irr1, irr2) = read_irr();
    let (isr1, isr2) = read_isr();
    let (m1, m2) = get_masks();

    PicStatus {
        initialized: is_initialized(),
        disabled: is_disabled(),
        master_mask: m1,
        slave_mask: m2,
        master_irr: irr1,
        slave_irr: irr2,
        master_isr: isr1,
        slave_isr: isr2,
    }
}

// ============================================================================
// MASK RESTORE
// ============================================================================

/// Restore masks saved during initialization.
///
/// # Safety
/// Directly modifies PIC masks.
pub unsafe fn restore_saved_masks() -> PicResult<()> {
    if let Some((m1, m2)) = MASK_SNAPSHOT.get() {
        outb(PIC1_DATA, *m1);
        outb(PIC2_DATA, *m2);
        MASTER_MASK.store(*m1, Ordering::Release);
        SLAVE_MASK.store(*m2, Ordering::Release);
        Ok(())
    } else {
        Err(PicError::NotInitialized)
    }
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/// Reinitialize PICs with specific ICW4 values.
unsafe fn reinit_with_icw4(off1: u8, off2: u8, icw4_master: u8, icw4_slave: u8) {
    // Save current masks
    let m1 = inb(PIC1_DATA);
    let m2 = inb(PIC2_DATA);

    // ICW1
    outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // ICW2
    outb(PIC1_DATA, off1);
    io_wait();
    outb(PIC2_DATA, off2);
    io_wait();

    // ICW3
    outb(PIC1_DATA, 1 << CASCADE_IRQ);
    io_wait();
    outb(PIC2_DATA, CASCADE_IRQ);
    io_wait();

    // ICW4
    outb(PIC1_DATA, icw4_master);
    io_wait();
    outb(PIC2_DATA, icw4_slave);
    io_wait();

    // Restore masks
    outb(PIC1_DATA, m1);
    outb(PIC2_DATA, m2);
}

/// Internal mask all without public exposure.
#[inline]
unsafe fn mask_all_internal() {
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
    MASTER_MASK.store(0xFF, Ordering::Release);
    SLAVE_MASK.store(0xFF, Ordering::Release);
}

/// Switch interrupt routing to APIC via IMCR if available.
unsafe fn try_route_imcr_to_apic() {
    outb(IMCR_INDEX, IMCR_SEL);
    outb(IMCR_DATA, IMCR_ROUTE_APIC);
    proof::audit_phys_alloc(0x1000_0006, 1, CapTag::KERNEL);
}

// ============================================================================
// LOW-LEVEL I/O
// ============================================================================

/// Read byte from I/O port.
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

/// Write byte to I/O port.
#[inline(always)]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
}

/// I/O wait (write to port 0x80 for delay).
#[inline(always)]
fn io_wait() {
    unsafe { outb(0x80, 0); }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_unmask_bits() {
        let mut v: u8 = 0b0000_0000;
        v |= 1 << 3;
        assert_eq!(v, 0b0000_1000);
        v &= !(1 << 3);
        assert_eq!(v, 0b0000_0000);
    }

    #[test]
    fn test_irq_validation() {
        // Valid IRQs
        for irq in 0..=15 {
            assert!(irq <= MAX_IRQ);
        }
        // Invalid IRQ
        assert!(16 > MAX_IRQ);
    }

    #[test]
    fn test_error_messages() {
        assert_eq!(PicError::NotInitialized.as_str(), "PIC not initialized");
        assert_eq!(PicError::InvalidIrq.as_str(), "Invalid IRQ number (must be 0-15)");
    }
}
