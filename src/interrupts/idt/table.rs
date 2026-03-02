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

use lazy_static::lazy_static;
use x86_64::structures::idt::InterruptDescriptorTable;
use x86_64::PrivilegeLevel;
use x86_64::VirtAddr;

use crate::arch::x86_64::gdt;
use crate::interrupts::isr;
use super::vectors;

lazy_static! {
    pub static ref IDT: InterruptDescriptorTable = build_idt();
}

fn build_idt() -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();

    configure_exceptions(&mut idt);
    configure_irqs(&mut idt);
    configure_syscall(&mut idt);

    idt
}

fn configure_exceptions(idt: &mut InterruptDescriptorTable) {
    idt.divide_error.set_handler_fn(isr::isr_divide_error);
    idt.debug.set_handler_fn(isr::isr_debug);

    // SAFETY: NMI uses dedicated IST stack to handle nested NMIs safely
    unsafe {
        idt.non_maskable_interrupt
            .set_handler_fn(isr::isr_nmi)
            .set_stack_index(gdt::NMI_IST_INDEX);
    }

    idt.breakpoint.set_handler_fn(isr::isr_breakpoint);
    idt.overflow.set_handler_fn(isr::isr_overflow);
    idt.bound_range_exceeded.set_handler_fn(isr::isr_bound_range);
    idt.invalid_opcode.set_handler_fn(isr::isr_invalid_opcode);
    idt.device_not_available.set_handler_fn(isr::isr_device_na);

    // SAFETY: Double fault uses dedicated IST stack to recover from stack overflow
    unsafe {
        idt.double_fault
            .set_handler_addr(VirtAddr::new(isr::isr_double_fault as *const () as u64))
            .set_stack_index(gdt::DF_IST_INDEX);
    }

    idt.invalid_tss.set_handler_fn(isr::isr_invalid_tss);
    idt.segment_not_present.set_handler_fn(isr::isr_segment_not_present);
    idt.stack_segment_fault.set_handler_fn(isr::isr_stack_segment_fault);
    idt.general_protection_fault.set_handler_fn(isr::isr_gpf);

    // SAFETY: Page fault uses dedicated IST stack for guard page handling
    unsafe {
        idt.page_fault
            .set_handler_fn(isr::isr_page_fault)
            .set_stack_index(gdt::PF_IST_INDEX);
    }

    idt.x87_floating_point.set_handler_fn(isr::isr_x87_fp);
    idt.alignment_check.set_handler_fn(isr::isr_alignment_check);

    // SAFETY: Machine check uses dedicated IST stack for critical hardware errors
    unsafe {
        idt.machine_check
            .set_handler_addr(VirtAddr::new(isr::isr_machine_check as *const () as u64))
            .set_stack_index(gdt::MC_IST_INDEX);
    }

    idt.simd_floating_point.set_handler_fn(isr::isr_simd_fp);
    idt.virtualization.set_handler_fn(isr::isr_virtualization);
}

fn configure_irqs(idt: &mut InterruptDescriptorTable) {
    idt[vectors::VECTOR_TIMER as usize].set_handler_fn(isr::irq_timer);
    idt[vectors::VECTOR_KEYBOARD as usize].set_handler_fn(isr::irq_keyboard);
    idt[vectors::VECTOR_MOUSE as usize].set_handler_fn(isr::irq_mouse);
}

fn configure_syscall(idt: &mut InterruptDescriptorTable) {
    idt[vectors::VECTOR_SYSCALL as usize]
        .set_handler_fn(isr::irq_syscall)
        .set_privilege_level(PrivilegeLevel::Ring3);
}
