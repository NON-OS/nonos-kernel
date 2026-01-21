// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::arch::asm;
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use crate::arch::x86_64::idt::constants::*;
use crate::arch::x86_64::idt::entry::{IdtEntry, InterruptFrame};
use crate::arch::x86_64::idt::error::IdtError;
use crate::arch::x86_64::idt::handlers::*;
use crate::arch::x86_64::idt::state::*;
use crate::arch::x86_64::idt::table::IdtPtr;

pub fn init() -> Result<(), IdtError> {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return Err(IdtError::AlreadyInitialized);
    }

    // SAFETY: IDT is only accessed during single-threaded initialization.
    unsafe {
        let idt = addr_of_mut!(IDT);

        (*idt).entries[0] = IdtEntry::interrupt_gate(isr_0, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[1] = IdtEntry::interrupt_gate(isr_1, KERNEL_CS, IST_DEBUG, DPL_KERNEL);
        (*idt).entries[2] = IdtEntry::interrupt_gate(isr_2, KERNEL_CS, IST_NMI, DPL_KERNEL);
        (*idt).entries[3] = IdtEntry::trap_gate(isr_3, KERNEL_CS, 0, DPL_USER);
        (*idt).entries[4] = IdtEntry::trap_gate(isr_4, KERNEL_CS, 0, DPL_USER);
        (*idt).entries[5] = IdtEntry::interrupt_gate(isr_5, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[6] = IdtEntry::interrupt_gate(isr_6, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[7] = IdtEntry::interrupt_gate(isr_7, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[8] =
            IdtEntry::interrupt_gate(isr_8, KERNEL_CS, IST_DOUBLE_FAULT, DPL_KERNEL);
        (*idt).entries[9] = IdtEntry::interrupt_gate(isr_9, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[10] = IdtEntry::interrupt_gate(isr_10, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[11] = IdtEntry::interrupt_gate(isr_11, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[12] = IdtEntry::interrupt_gate(isr_12, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[13] = IdtEntry::interrupt_gate(isr_13, KERNEL_CS, IST_GP, DPL_KERNEL);
        (*idt).entries[14] =
            IdtEntry::interrupt_gate(isr_14, KERNEL_CS, IST_PAGE_FAULT, DPL_KERNEL);
        (*idt).entries[15] = IdtEntry::interrupt_gate(isr_15, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[16] = IdtEntry::interrupt_gate(isr_16, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[17] = IdtEntry::interrupt_gate(isr_17, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[18] =
            IdtEntry::interrupt_gate(isr_18, KERNEL_CS, IST_MACHINE_CHECK, DPL_KERNEL);
        (*idt).entries[19] = IdtEntry::interrupt_gate(isr_19, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[20] = IdtEntry::interrupt_gate(isr_20, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[21] = IdtEntry::interrupt_gate(isr_21, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[22] = IdtEntry::interrupt_gate(isr_22, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[23] = IdtEntry::interrupt_gate(isr_23, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[24] = IdtEntry::interrupt_gate(isr_24, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[25] = IdtEntry::interrupt_gate(isr_25, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[26] = IdtEntry::interrupt_gate(isr_26, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[27] = IdtEntry::interrupt_gate(isr_27, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[28] = IdtEntry::interrupt_gate(isr_28, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[29] = IdtEntry::interrupt_gate(isr_29, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[30] = IdtEntry::interrupt_gate(isr_30, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[31] = IdtEntry::interrupt_gate(isr_31, KERNEL_CS, 0, DPL_KERNEL);

        (*idt).entries[32] = IdtEntry::interrupt_gate(isr_32, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[33] = IdtEntry::interrupt_gate(isr_33, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[34] = IdtEntry::interrupt_gate(isr_34, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[35] = IdtEntry::interrupt_gate(isr_35, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[36] = IdtEntry::interrupt_gate(isr_36, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[37] = IdtEntry::interrupt_gate(isr_37, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[38] = IdtEntry::interrupt_gate(isr_38, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[39] = IdtEntry::interrupt_gate(isr_39, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[40] = IdtEntry::interrupt_gate(isr_40, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[41] = IdtEntry::interrupt_gate(isr_41, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[42] = IdtEntry::interrupt_gate(isr_42, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[43] = IdtEntry::interrupt_gate(isr_43, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[44] = IdtEntry::interrupt_gate(isr_44, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[45] = IdtEntry::interrupt_gate(isr_45, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[46] = IdtEntry::interrupt_gate(isr_46, KERNEL_CS, 0, DPL_KERNEL);
        (*idt).entries[47] = IdtEntry::interrupt_gate(isr_47, KERNEL_CS, 0, DPL_KERNEL);

        (*idt).entries[0x80] = IdtEntry::trap_gate(isr_syscall, KERNEL_CS, 0, DPL_USER);

        remap_pic();
        load_idt();
    }

    Ok(())
}

unsafe fn load_idt() {
    // SAFETY: Reading IDT address for LIDT instruction during single-threaded init.
    unsafe {
        let idt_ptr = addr_of_mut!(IDT);
        let ptr = IdtPtr {
            limit: (core::mem::size_of::<[IdtEntry; IDT_ENTRIES]>() - 1) as u16,
            base: (*idt_ptr).entries.as_ptr() as u64,
        };

        asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags));
    }
}

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

pub fn register_irq_handler(irq: u8, handler: fn(u8)) -> Result<(), IdtError> {
    if irq >= 16 {
        return Err(IdtError::InvalidVector);
    }

    // SAFETY: IRQ_HANDLERS is only modified during handler registration.
    unsafe {
        IRQ_HANDLERS[irq as usize] = Some(handler);
    }

    Ok(())
}

pub fn unregister_irq_handler(irq: u8) -> Result<(), IdtError> {
    if irq >= 16 {
        return Err(IdtError::InvalidVector);
    }

    // SAFETY: IRQ_HANDLERS is only modified during handler registration.
    unsafe {
        IRQ_HANDLERS[irq as usize] = None;
    }

    Ok(())
}

pub fn register_syscall_handler(handler: fn(&mut InterruptFrame)) {
    // SAFETY: SYSCALL_HANDLER is only modified during handler registration.
    unsafe {
        SYSCALL_HANDLER = Some(handler);
    }
}

pub fn register_handler(vector: u8, handler: fn(&mut InterruptFrame)) -> Result<(), IdtError> {
    if vector < 32 {
        return Err(IdtError::ReservedVector);
    }

    // SAFETY: OTHER_HANDLERS is only modified during handler registration.
    unsafe {
        OTHER_HANDLERS[vector as usize] = Some(handler);
    }

    Ok(())
}

pub fn remap_pic() {
    // SAFETY: Remapping PIC during initialization.
    unsafe {
        let mask1 = inb(PIC1_DATA);
        let mask2 = inb(PIC2_DATA);

        outb(PIC1_COMMAND, ICW1_INIT);
        io_wait();
        outb(PIC2_COMMAND, ICW1_INIT);
        io_wait();

        outb(PIC1_DATA, IRQ_BASE);
        io_wait();
        outb(PIC2_DATA, IRQ_BASE + 8);
        io_wait();

        outb(PIC1_DATA, 4);
        io_wait();
        outb(PIC2_DATA, 2);
        io_wait();

        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);
    }
}

pub fn disable_pic() {
    // SAFETY: Disabling PIC by masking all interrupts.
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
    }
}

pub fn set_pic_masks(mask1: u8, mask2: u8) {
    // SAFETY: Setting PIC masks.
    unsafe {
        outb(PIC1_DATA, mask1);
        outb(PIC2_DATA, mask2);
    }
}

pub fn get_pic_masks() -> (u8, u8) {
    // SAFETY: Reading PIC masks.
    unsafe { (inb(PIC1_DATA), inb(PIC2_DATA)) }
}

#[inline]
pub fn enable() {
    // SAFETY: Enabling interrupts via STI instruction.
    unsafe {
        asm!("sti", options(nomem, nostack));
    }
}

#[inline]
pub fn disable() {
    // SAFETY: Disabling interrupts via CLI instruction.
    unsafe {
        asm!("cli", options(nomem, nostack));
    }
}

#[inline]
pub fn are_enabled() -> bool {
    let flags: u64;
    // SAFETY: Reading RFLAGS to check interrupt flag.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            out(reg) flags,
            options(nomem, preserves_flags)
        );
    }
    (flags & (1 << 9)) != 0
}

pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let were_enabled = are_enabled();
    disable();
    let result = f();
    if were_enabled {
        enable();
    }
    result
}

#[derive(Debug, Clone, Copy, Default)]
pub struct IdtStats {
    pub total_interrupts: u64,
    pub exceptions: u64,
    pub irqs: u64,
    pub initialized: bool,
}

pub fn get_stats() -> IdtStats {
    IdtStats {
        total_interrupts: TOTAL_INTERRUPTS.load(Ordering::Relaxed),
        exceptions: EXCEPTION_COUNT.load(Ordering::Relaxed),
        irqs: IRQ_COUNT.load(Ordering::Relaxed),
        initialized: INITIALIZED.load(Ordering::Relaxed),
    }
}

pub fn get_vector_count(vector: u8) -> u64 {
    INTERRUPT_COUNTS[vector as usize].load(Ordering::Relaxed)
}
