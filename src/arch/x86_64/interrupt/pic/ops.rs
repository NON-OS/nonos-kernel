// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use alloc::format;
use core::sync::atomic::Ordering;

use crate::memory::proof::{self, CapTag};
use super::constants::*;
use super::error::{PicError, PicResult};
use super::state::*;
use super::io::*;
use super::mask::{mask_all_internal, get_masks};

pub unsafe fn enable_aeoi() -> PicResult<()> {
    unsafe {
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
}

pub unsafe fn disable_aeoi() -> PicResult<()> {
    unsafe {
        if !is_initialized() {
            return Err(PicError::NotInitialized);
        }

        reinit_with_icw4(0x20, 0x28, ICW4_8086, ICW4_8086);
        mask_all_internal();

        proof::audit_phys_alloc(0x8259_0003, 0, CapTag::KERNEL);
        Ok(())
    }
}

pub unsafe fn enable_smm() -> PicResult<()> {
    unsafe {
        if !is_initialized() {
            return Err(PicError::NotInitialized);
        }

        outb(PIC1_CMD, 0x68);
        outb(PIC2_CMD, 0x68);

        proof::audit_phys_alloc(0x8259_0004, 1, CapTag::KERNEL);
        Ok(())
    }
}

pub unsafe fn disable_smm() -> PicResult<()> {
    unsafe {
        if !is_initialized() {
            return Err(PicError::NotInitialized);
        }

        outb(PIC1_CMD, 0x48);
        outb(PIC2_CMD, 0x48);

        proof::audit_phys_alloc(0x8259_0005, 0, CapTag::KERNEL);
        Ok(())
    }
}

pub fn read_irr() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
        (inb(PIC1_CMD), inb(PIC2_CMD))
    }
}

pub fn read_isr() -> (u8, u8) {
    read_isr_internal()
}

pub(crate) fn read_isr_internal() -> (u8, u8) {
    unsafe {
        outb(PIC1_CMD, OCW3_READ_ISR);
        outb(PIC2_CMD, OCW3_READ_ISR);
        (inb(PIC2_CMD), inb(PIC1_CMD))
    }
}

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

pub unsafe fn restore_saved_masks() -> PicResult<()> {
    unsafe {
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
}

unsafe fn reinit_with_icw4(off1: u8, off2: u8, icw4_master: u8, icw4_slave: u8) {
    unsafe {
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

        outb(PIC1_DATA, 1 << CASCADE_IRQ);
        io_wait();
        outb(PIC2_DATA, CASCADE_IRQ);
        io_wait();

        outb(PIC1_DATA, icw4_master);
        io_wait();
        outb(PIC2_DATA, icw4_slave);
        io_wait();

        outb(PIC1_DATA, m1);
        outb(PIC2_DATA, m2);
    }
}
