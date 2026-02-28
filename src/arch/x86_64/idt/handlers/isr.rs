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

macro_rules! exception_stub_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                "push {}",
                "jmp interrupt_common",
                const $vector,
            );
        }
    };
}

macro_rules! exception_stub_with_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push {}",
                "jmp interrupt_common",
                const $vector,
            );
        }
    };
}

macro_rules! irq_stub {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        #[no_mangle]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push 0",
                "push {}",
                "jmp interrupt_common",
                const $vector,
            );
        }
    };
}

exception_stub_no_error!(isr_divide_error, 0);
exception_stub_no_error!(isr_debug, 1);
exception_stub_no_error!(isr_nmi, 2);
exception_stub_no_error!(isr_breakpoint, 3);
exception_stub_no_error!(isr_overflow, 4);
exception_stub_no_error!(isr_bound_range, 5);
exception_stub_no_error!(isr_invalid_opcode, 6);
exception_stub_no_error!(isr_device_not_available, 7);
exception_stub_with_error!(isr_double_fault, 8);
exception_stub_no_error!(isr_coprocessor_segment, 9);
exception_stub_with_error!(isr_invalid_tss, 10);
exception_stub_with_error!(isr_segment_not_present, 11);
exception_stub_with_error!(isr_stack_segment, 12);
exception_stub_with_error!(isr_general_protection, 13);
exception_stub_with_error!(isr_page_fault, 14);
exception_stub_no_error!(isr_reserved_15, 15);
exception_stub_no_error!(isr_x87_fp, 16);
exception_stub_with_error!(isr_alignment_check, 17);
exception_stub_no_error!(isr_machine_check, 18);
exception_stub_no_error!(isr_simd_fp, 19);
exception_stub_no_error!(isr_virtualization, 20);
exception_stub_with_error!(isr_control_protection, 21);
exception_stub_no_error!(isr_reserved_22, 22);
exception_stub_no_error!(isr_reserved_23, 23);
exception_stub_no_error!(isr_reserved_24, 24);
exception_stub_no_error!(isr_reserved_25, 25);
exception_stub_no_error!(isr_reserved_26, 26);
exception_stub_no_error!(isr_reserved_27, 27);
exception_stub_no_error!(isr_reserved_28, 28);
exception_stub_no_error!(isr_reserved_29, 29);
exception_stub_no_error!(isr_reserved_30, 30);
exception_stub_no_error!(isr_reserved_31, 31);

irq_stub!(isr_irq0, 32);
irq_stub!(isr_irq1, 33);
irq_stub!(isr_irq2, 34);
irq_stub!(isr_irq3, 35);
irq_stub!(isr_irq4, 36);
irq_stub!(isr_irq5, 37);
irq_stub!(isr_irq6, 38);
irq_stub!(isr_irq7, 39);
irq_stub!(isr_irq8, 40);
irq_stub!(isr_irq9, 41);
irq_stub!(isr_irq10, 42);
irq_stub!(isr_irq11, 43);
irq_stub!(isr_irq12, 44);
irq_stub!(isr_irq13, 45);
irq_stub!(isr_irq14, 46);
irq_stub!(isr_irq15, 47);

irq_stub!(isr_generic_48, 48);
irq_stub!(isr_syscall, 0x80);
