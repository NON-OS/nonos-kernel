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

use super::constants::*;
use super::error::{PicError, PicResult};
use super::io::{inb, io_wait, outb};
use super::state::*;
use crate::memory::proof::{self, CapTag};
use core::sync::atomic::Ordering;

pub unsafe fn restore_saved_masks() -> PicResult<()> {
    unsafe {
        if let Some((m1, m2)) = MASK_SNAPSHOT.get() {
            outb(PIC1_DATA, *m1);
            outb(PIC2_DATA, *m2);
            MASTER_MASK.store(*m1, Ordering::Release);
            SLAVE_MASK.store(*m2, Ordering::Release);
            proof::audit_phys_alloc(0x8259_0006, ((*m1 as u64) << 8) | *m2 as u64, CapTag::KERNEL);
            Ok(())
        } else {
            Err(PicError::NotInitialized)
        }
    }
}

pub(super) unsafe fn reinit_with_icw4(off1: u8, off2: u8, icw4_master: u8, icw4_slave: u8) {
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
        proof::audit_phys_alloc(
            0x8259_0007,
            ((off1 as u64) << 24)
                | ((off2 as u64) << 16)
                | ((icw4_master as u64) << 8)
                | icw4_slave as u64,
            CapTag::KERNEL,
        );
    }
}
