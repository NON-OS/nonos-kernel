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

use x86_64::PrivilegeLevel;

use crate::interrupts::idt::vectors;
use crate::interrupts::*;

#[test]
fn test_timer_interrupt_id() {
    assert_eq!(TIMER_INTERRUPT_ID, 32);
}

#[test]
fn test_keyboard_interrupt_id() {
    assert_eq!(KEYBOARD_INTERRUPT_ID, 33);
}

#[test]
fn test_mouse_interrupt_id() {
    assert_eq!(MOUSE_INTERRUPT_ID, 44);
}

#[test]
fn test_syscall_interrupt_id() {
    assert_eq!(SYSCALL_INTERRUPT_ID, 0x80);
}

#[test]
fn test_double_fault_ist_index() {
    assert!(DOUBLE_FAULT_IST_INDEX <= 6);
}

#[test]
fn test_page_fault_ist_index() {
    assert!(PAGE_FAULT_IST_INDEX <= 6);
}

#[test]
fn test_nmi_ist_index() {
    assert!(NMI_IST_INDEX <= 6);
}

#[test]
fn test_machine_check_ist_index() {
    assert!(MACHINE_CHECK_IST_INDEX <= 6);
}

#[test]
fn test_gate_type_interrupt_value() {
    assert_eq!(GateType::Interrupt as u8, 0xE);
}

#[test]
fn test_gate_type_trap_value() {
    assert_eq!(GateType::Trap as u8, 0xF);
}

#[test]
fn test_entry_options_new() {
    let opts = EntryOptions::new();
    assert_eq!(opts.gate_type, GateType::Interrupt);
    assert_eq!(opts.privilege_level, PrivilegeLevel::Ring0);
    assert!(opts.present);
    assert!(opts.ist_index.is_none());
}

#[test]
fn test_entry_options_interrupt() {
    let opts = EntryOptions::interrupt();
    assert_eq!(opts.gate_type, GateType::Interrupt);
    assert!(opts.present);
}

#[test]
fn test_entry_options_trap() {
    let opts = EntryOptions::trap();
    assert_eq!(opts.gate_type, GateType::Trap);
    assert!(opts.present);
}

#[test]
fn test_entry_options_with_privilege_level() {
    let opts = EntryOptions::new().with_privilege_level(PrivilegeLevel::Ring3);
    assert_eq!(opts.privilege_level, PrivilegeLevel::Ring3);
}

#[test]
fn test_entry_options_with_ist_index() {
    let opts = EntryOptions::new().with_ist_index(1);
    assert_eq!(opts.ist_index, Some(1));
}

#[test]
fn test_entry_options_user_callable() {
    let opts = EntryOptions::new().user_callable();
    assert_eq!(opts.privilege_level, PrivilegeLevel::Ring3);
}

#[test]
fn test_entry_options_default() {
    let opts = EntryOptions::default();
    assert_eq!(opts.gate_type, GateType::Interrupt);
    assert!(opts.present);
}

#[test]
fn test_entry_error_invalid_ist_index_str() {
    assert_eq!(EntryError::InvalidIstIndex.as_str(), "IST index must be 0-6");
}

#[test]
fn test_entry_error_handler_not_present_str() {
    assert_eq!(EntryError::HandlerNotPresent.as_str(), "Handler address is null");
}

#[test]
fn test_validate_ist_index_valid() {
    assert!(validate_ist_index(0).is_ok());
    assert!(validate_ist_index(6).is_ok());
}

#[test]
fn test_validate_ist_index_invalid() {
    assert_eq!(validate_ist_index(7), Err(EntryError::InvalidIstIndex));
    assert_eq!(validate_ist_index(255), Err(EntryError::InvalidIstIndex));
}

#[test]
fn test_validate_handler_address_valid() {
    assert!(validate_handler_address(0x1000).is_ok());
    assert!(validate_handler_address(u64::MAX).is_ok());
}

#[test]
fn test_validate_handler_address_null() {
    assert_eq!(validate_handler_address(0), Err(EntryError::HandlerNotPresent));
}

#[test]
fn test_vector_constants_divide_error() {
    assert_eq!(vectors::VECTOR_DIVIDE_ERROR, 0);
}

#[test]
fn test_vector_constants_debug() {
    assert_eq!(vectors::VECTOR_DEBUG, 1);
}

#[test]
fn test_vector_constants_nmi() {
    assert_eq!(vectors::VECTOR_NMI, 2);
}

#[test]
fn test_vector_constants_breakpoint() {
    assert_eq!(vectors::VECTOR_BREAKPOINT, 3);
}

#[test]
fn test_vector_constants_overflow() {
    assert_eq!(vectors::VECTOR_OVERFLOW, 4);
}

#[test]
fn test_vector_constants_bound_range() {
    assert_eq!(vectors::VECTOR_BOUND_RANGE, 5);
}

#[test]
fn test_vector_constants_invalid_opcode() {
    assert_eq!(vectors::VECTOR_INVALID_OPCODE, 6);
}

#[test]
fn test_vector_constants_device_not_available() {
    assert_eq!(vectors::VECTOR_DEVICE_NOT_AVAILABLE, 7);
}

#[test]
fn test_vector_constants_double_fault() {
    assert_eq!(vectors::VECTOR_DOUBLE_FAULT, 8);
}

#[test]
fn test_vector_constants_invalid_tss() {
    assert_eq!(vectors::VECTOR_INVALID_TSS, 10);
}

#[test]
fn test_vector_constants_segment_not_present() {
    assert_eq!(vectors::VECTOR_SEGMENT_NOT_PRESENT, 11);
}

#[test]
fn test_vector_constants_stack_segment_fault() {
    assert_eq!(vectors::VECTOR_STACK_SEGMENT_FAULT, 12);
}

#[test]
fn test_vector_constants_general_protection() {
    assert_eq!(vectors::VECTOR_GENERAL_PROTECTION, 13);
}

#[test]
fn test_vector_constants_page_fault() {
    assert_eq!(vectors::VECTOR_PAGE_FAULT, 14);
}

#[test]
fn test_vector_constants_x87_fp() {
    assert_eq!(vectors::VECTOR_X87_FLOATING_POINT, 16);
}

#[test]
fn test_vector_constants_alignment_check() {
    assert_eq!(vectors::VECTOR_ALIGNMENT_CHECK, 17);
}

#[test]
fn test_vector_constants_machine_check() {
    assert_eq!(vectors::VECTOR_MACHINE_CHECK, 18);
}

#[test]
fn test_vector_constants_simd_fp() {
    assert_eq!(vectors::VECTOR_SIMD_FLOATING_POINT, 19);
}

#[test]
fn test_vector_constants_virtualization() {
    assert_eq!(vectors::VECTOR_VIRTUALIZATION, 20);
}

#[test]
fn test_vector_constants_timer() {
    assert_eq!(vectors::VECTOR_TIMER, 32);
}

#[test]
fn test_vector_constants_keyboard() {
    assert_eq!(vectors::VECTOR_KEYBOARD, 33);
}

#[test]
fn test_vector_constants_mouse() {
    assert_eq!(vectors::VECTOR_MOUSE, 44);
}

#[test]
fn test_vector_constants_syscall() {
    assert_eq!(vectors::VECTOR_SYSCALL, 0x80);
}

#[test]
fn test_vector_constants_apic_spurious() {
    assert_eq!(vectors::VECTOR_APIC_SPURIOUS, 0xFF);
}

#[test]
fn test_vector_constants_apic_error() {
    assert_eq!(vectors::VECTOR_APIC_ERROR, 0xFE);
}

#[test]
fn test_exception_vector_range() {
    assert_eq!(vectors::EXCEPTION_VECTOR_START, 0);
    assert_eq!(vectors::EXCEPTION_VECTOR_END, 31);
}

#[test]
fn test_irq_vector_range() {
    assert_eq!(vectors::IRQ_VECTOR_START, 32);
    assert_eq!(vectors::IRQ_VECTOR_END, 47);
}

#[test]
fn test_user_vector_range() {
    assert_eq!(vectors::USER_VECTOR_START, 48);
    assert_eq!(vectors::USER_VECTOR_END, 0xEF);
}

#[test]
fn test_is_exception() {
    assert!(is_exception(0));
    assert!(is_exception(14));
    assert!(is_exception(31));
    assert!(!is_exception(32));
    assert!(!is_exception(128));
}

#[test]
fn test_is_irq() {
    assert!(!is_irq(31));
    assert!(is_irq(32));
    assert!(is_irq(47));
    assert!(!is_irq(48));
}

#[test]
fn test_is_user_allocatable() {
    assert!(!is_user_allocatable(31));
    assert!(!is_user_allocatable(32));
    assert!(!is_user_allocatable(47));
    assert!(is_user_allocatable(48));
    assert!(is_user_allocatable(0xEF));
    assert!(!is_user_allocatable(0xF0));
}

#[test]
fn test_irq_to_vector() {
    assert_eq!(irq_to_vector(0), 32);
    assert_eq!(irq_to_vector(1), 33);
    assert_eq!(irq_to_vector(15), 47);
}

#[test]
fn test_vector_to_irq_valid() {
    assert_eq!(vector_to_irq(32), Some(0));
    assert_eq!(vector_to_irq(33), Some(1));
    assert_eq!(vector_to_irq(47), Some(15));
}

#[test]
fn test_vector_to_irq_invalid() {
    assert_eq!(vector_to_irq(0), None);
    assert_eq!(vector_to_irq(31), None);
    assert_eq!(vector_to_irq(48), None);
    assert_eq!(vector_to_irq(128), None);
}

#[test]
fn test_exception_name_divide_error() {
    assert_eq!(exception_name(0), "Divide Error");
}

#[test]
fn test_exception_name_debug() {
    assert_eq!(exception_name(1), "Debug");
}

#[test]
fn test_exception_name_nmi() {
    assert_eq!(exception_name(2), "Non-Maskable Interrupt");
}

#[test]
fn test_exception_name_breakpoint() {
    assert_eq!(exception_name(3), "Breakpoint");
}

#[test]
fn test_exception_name_page_fault() {
    assert_eq!(exception_name(14), "Page Fault");
}

#[test]
fn test_exception_name_double_fault() {
    assert_eq!(exception_name(8), "Double Fault");
}

#[test]
fn test_exception_name_gpf() {
    assert_eq!(exception_name(13), "General Protection Fault");
}

#[test]
fn test_exception_name_reserved() {
    assert_eq!(exception_name(15), "Reserved");
    assert_eq!(exception_name(22), "Reserved");
}

#[test]
fn test_exception_has_error_code_double_fault() {
    assert!(exception_has_error_code(8));
}

#[test]
fn test_exception_has_error_code_invalid_tss() {
    assert!(exception_has_error_code(10));
}

#[test]
fn test_exception_has_error_code_segment_not_present() {
    assert!(exception_has_error_code(11));
}

#[test]
fn test_exception_has_error_code_stack_segment() {
    assert!(exception_has_error_code(12));
}

#[test]
fn test_exception_has_error_code_gpf() {
    assert!(exception_has_error_code(13));
}

#[test]
fn test_exception_has_error_code_page_fault() {
    assert!(exception_has_error_code(14));
}

#[test]
fn test_exception_has_error_code_alignment_check() {
    assert!(exception_has_error_code(17));
}

#[test]
fn test_exception_has_no_error_code_divide() {
    assert!(!exception_has_error_code(0));
}

#[test]
fn test_exception_has_no_error_code_debug() {
    assert!(!exception_has_error_code(1));
}

#[test]
fn test_exception_has_no_error_code_breakpoint() {
    assert!(!exception_has_error_code(3));
}

#[test]
fn test_exception_is_fatal_divide() {
    assert!(exception_is_fatal(0));
}

#[test]
fn test_exception_is_fatal_invalid_opcode() {
    assert!(exception_is_fatal(6));
}

#[test]
fn test_exception_is_fatal_double_fault() {
    assert!(exception_is_fatal(8));
}

#[test]
fn test_exception_is_fatal_gpf() {
    assert!(exception_is_fatal(13));
}

#[test]
fn test_exception_is_fatal_machine_check() {
    assert!(exception_is_fatal(18));
}

#[test]
fn test_exception_not_fatal_page_fault() {
    assert!(!exception_is_fatal(14));
}

#[test]
fn test_exception_not_fatal_debug() {
    assert!(!exception_is_fatal(1));
}

#[test]
fn test_exception_not_fatal_breakpoint() {
    assert!(!exception_is_fatal(3));
}
