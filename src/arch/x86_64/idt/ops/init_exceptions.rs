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

use super::super::constants::*;
use super::super::entry::IdtEntry;
use super::super::handlers::*;
use super::super::table::Idt;

pub unsafe fn setup_exceptions(idt: &mut Idt) {
    idt.entries[0] = IdtEntry::interrupt_gate(isr_0, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[1] = IdtEntry::interrupt_gate(isr_1, KERNEL_CS, IST_DEBUG, DPL_KERNEL);
    idt.entries[2] = IdtEntry::interrupt_gate(isr_2, KERNEL_CS, IST_NMI, DPL_KERNEL);
    idt.entries[3] = IdtEntry::trap_gate(isr_3, KERNEL_CS, 0, DPL_USER);
    idt.entries[4] = IdtEntry::trap_gate(isr_4, KERNEL_CS, 0, DPL_USER);
    idt.entries[5] = IdtEntry::interrupt_gate(isr_5, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[6] = IdtEntry::interrupt_gate(isr_6, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[7] = IdtEntry::interrupt_gate(isr_7, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[8] = IdtEntry::interrupt_gate(isr_8, KERNEL_CS, IST_DOUBLE_FAULT, DPL_KERNEL);
    idt.entries[9] = IdtEntry::interrupt_gate(isr_9, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[10] = IdtEntry::interrupt_gate(isr_10, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[11] = IdtEntry::interrupt_gate(isr_11, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[12] = IdtEntry::interrupt_gate(isr_12, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[13] = IdtEntry::interrupt_gate(isr_13, KERNEL_CS, IST_GP, DPL_KERNEL);
    idt.entries[14] = IdtEntry::interrupt_gate(isr_14, KERNEL_CS, IST_PAGE_FAULT, DPL_KERNEL);
    idt.entries[15] = IdtEntry::interrupt_gate(isr_15, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[16] = IdtEntry::interrupt_gate(isr_16, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[17] = IdtEntry::interrupt_gate(isr_17, KERNEL_CS, 0, DPL_KERNEL);
    idt.entries[18] = IdtEntry::interrupt_gate(isr_18, KERNEL_CS, IST_MACHINE_CHECK, DPL_KERNEL);
    for i in 19..32 {
        idt.entries[i] = IdtEntry::interrupt_gate(
            match i {
                19 => isr_19,
                20 => isr_20,
                21 => isr_21,
                22 => isr_22,
                23 => isr_23,
                24 => isr_24,
                25 => isr_25,
                26 => isr_26,
                27 => isr_27,
                28 => isr_28,
                29 => isr_29,
                30 => isr_30,
                _ => isr_31,
            },
            KERNEL_CS,
            0,
            DPL_KERNEL,
        );
    }
}
