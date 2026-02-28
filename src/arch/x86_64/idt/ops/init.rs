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

use core::arch::asm;
use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;

use super::super::constants::*;
use super::super::entry::IdtEntry;
use super::super::error::IdtError;
use super::super::handlers::*;
use super::super::state::{IDT, INITIALIZED};
use super::super::table::IdtPtr;
use super::pic::remap_pic;

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
