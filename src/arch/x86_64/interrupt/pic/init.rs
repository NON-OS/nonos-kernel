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

use crate::memory::proof::{self, CapTag};
use super::constants::*;
use super::error::{PicError, PicResult};
use super::state::*;
use super::io::*;
use super::mask::mask_all_internal;

pub unsafe fn init(master_offset: u8, slave_offset: u8) -> PicResult<()> {
    unsafe {
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(PicError::AlreadyInitialized);
        }

        let m1 = inb(PIC1_DATA);
        let m2 = inb(PIC2_DATA);
        MASK_SNAPSHOT.call_once(|| (m1, m2));

        outb(PIC1_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();
        outb(PIC2_CMD, ICW1_INIT | ICW1_ICW4);
        io_wait();

        outb(PIC1_DATA, master_offset);
        io_wait();
        outb(PIC2_DATA, slave_offset);
        io_wait();

        outb(PIC1_DATA, 1 << CASCADE_IRQ);
        io_wait();
        outb(PIC2_DATA, CASCADE_IRQ);
        io_wait();

        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        mask_all_internal();

        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);

        try_route_imcr_to_apic();

        proof::audit_phys_alloc(
            0x8259_0000,
            ((master_offset as u64) << 8) | slave_offset as u64,
            CapTag::KERNEL,
        );

        Ok(())
    }
}

pub unsafe fn init_default() -> PicResult<()> {
    unsafe { init(0x20, 0x28) }
}

pub fn disable_hard() {
    if DISABLED.swap(true, Ordering::SeqCst) {
        return;
    }

    unsafe {
        mask_all_internal();
        outb(PIC1_CMD, OCW3_READ_IRR);
        outb(PIC2_CMD, OCW3_READ_IRR);
    }

    proof::audit_phys_alloc(0x8259_0001, 0, CapTag::KERNEL);
}

unsafe fn try_route_imcr_to_apic() {
    unsafe {
        outb(IMCR_INDEX, IMCR_SEL);
        outb(IMCR_DATA, IMCR_ROUTE_APIC);
        proof::audit_phys_alloc(0x1000_0006, 1, CapTag::KERNEL);
    }
}
