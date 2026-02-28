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

use core::sync::atomic::Ordering;

use super::constants::*;
use super::error::{PicError, PicResult};
use super::state::*;
use super::io::*;

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

            let master = inb(PIC1_DATA);
            if (master & (1 << CASCADE_IRQ)) != 0 {
                outb(PIC1_DATA, master & !(1 << CASCADE_IRQ));
            }
        }
    }
    Ok(())
}

pub fn mask_all() {
    unsafe { mask_all_internal(); }
}

pub fn get_masks() -> (u8, u8) {
    (
        MASTER_MASK.load(Ordering::Acquire),
        SLAVE_MASK.load(Ordering::Acquire),
    )
}

pub unsafe fn set_masks(master: u8, slave: u8) {
    unsafe {
        outb(PIC1_DATA, master);
        outb(PIC2_DATA, slave);
        MASTER_MASK.store(master, Ordering::Release);
        SLAVE_MASK.store(slave, Ordering::Release);
    }
}

#[inline]
pub(crate) unsafe fn mask_all_internal() {
    unsafe {
        outb(PIC1_DATA, 0xFF);
        outb(PIC2_DATA, 0xFF);
        MASTER_MASK.store(0xFF, Ordering::Release);
        SLAVE_MASK.store(0xFF, Ordering::Release);
    }
}
