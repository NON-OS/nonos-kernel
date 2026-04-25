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

use crate::test::framework::TestResult;
use x86_64::PrivilegeLevel;

use crate::interrupts::idt::vectors;
use crate::interrupts::*;

pub(crate) fn test_timer_interrupt_id() -> TestResult {
    if TIMER_INTERRUPT_ID != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_keyboard_interrupt_id() -> TestResult {
    if KEYBOARD_INTERRUPT_ID != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mouse_interrupt_id() -> TestResult {
    if MOUSE_INTERRUPT_ID != 44 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_syscall_interrupt_id() -> TestResult {
    if SYSCALL_INTERRUPT_ID != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_double_fault_ist_index() -> TestResult {
    if !(DOUBLE_FAULT_IST_INDEX <= 6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_fault_ist_index() -> TestResult {
    if !(PAGE_FAULT_IST_INDEX <= 6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nmi_ist_index() -> TestResult {
    if !(NMI_IST_INDEX <= 6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_check_ist_index() -> TestResult {
    if !(MACHINE_CHECK_IST_INDEX <= 6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gate_type_interrupt_value() -> TestResult {
    if GateType::Interrupt as u8 != 0xE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gate_type_trap_value() -> TestResult {
    if GateType::Trap as u8 != 0xF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_new() -> TestResult {
    let opts = EntryOptions::new();
    if opts.gate_type != GateType::Interrupt {
        return TestResult::Fail;
    }
    if opts.privilege_level != PrivilegeLevel::Ring0 {
        return TestResult::Fail;
    }
    if !opts.present {
        return TestResult::Fail;
    }
    if opts.ist_index.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_interrupt() -> TestResult {
    let opts = EntryOptions::interrupt();
    if opts.gate_type != GateType::Interrupt {
        return TestResult::Fail;
    }
    if !opts.present {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_trap() -> TestResult {
    let opts = EntryOptions::trap();
    if opts.gate_type != GateType::Trap {
        return TestResult::Fail;
    }
    if !opts.present {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_with_privilege_level() -> TestResult {
    let opts = EntryOptions::new().with_privilege_level(PrivilegeLevel::Ring3);
    if opts.privilege_level != PrivilegeLevel::Ring3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_with_ist_index() -> TestResult {
    let opts = EntryOptions::new().with_ist_index(1);
    if opts.ist_index != Some(1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_user_callable() -> TestResult {
    let opts = EntryOptions::new().user_callable();
    if opts.privilege_level != PrivilegeLevel::Ring3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_options_default() -> TestResult {
    let opts = EntryOptions::default();
    if opts.gate_type != GateType::Interrupt {
        return TestResult::Fail;
    }
    if !opts.present {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_error_invalid_ist_index_str() -> TestResult {
    if EntryError::InvalidIstIndex.as_str() != "IST index must be 0-6" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_entry_error_handler_not_present_str() -> TestResult {
    if EntryError::HandlerNotPresent.as_str() != "Handler address is null" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_ist_index_valid() -> TestResult {
    if validate_ist_index(0).is_err() {
        return TestResult::Fail;
    }
    if validate_ist_index(6).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_ist_index_invalid() -> TestResult {
    if validate_ist_index(7) != Err(EntryError::InvalidIstIndex) {
        return TestResult::Fail;
    }
    if validate_ist_index(255) != Err(EntryError::InvalidIstIndex) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_handler_address_valid() -> TestResult {
    if validate_handler_address(0x1000).is_err() {
        return TestResult::Fail;
    }
    if validate_handler_address(u64::MAX).is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_validate_handler_address_null() -> TestResult {
    if validate_handler_address(0) != Err(EntryError::HandlerNotPresent) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_divide_error() -> TestResult {
    if vectors::VECTOR_DIVIDE_ERROR != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_debug() -> TestResult {
    if vectors::VECTOR_DEBUG != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_nmi() -> TestResult {
    if vectors::VECTOR_NMI != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_breakpoint() -> TestResult {
    if vectors::VECTOR_BREAKPOINT != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_overflow() -> TestResult {
    if vectors::VECTOR_OVERFLOW != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_bound_range() -> TestResult {
    if vectors::VECTOR_BOUND_RANGE != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_invalid_opcode() -> TestResult {
    if vectors::VECTOR_INVALID_OPCODE != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_device_not_available() -> TestResult {
    if vectors::VECTOR_DEVICE_NOT_AVAILABLE != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_double_fault() -> TestResult {
    if vectors::VECTOR_DOUBLE_FAULT != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_invalid_tss() -> TestResult {
    if vectors::VECTOR_INVALID_TSS != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_segment_not_present() -> TestResult {
    if vectors::VECTOR_SEGMENT_NOT_PRESENT != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_stack_segment_fault() -> TestResult {
    if vectors::VECTOR_STACK_SEGMENT_FAULT != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_general_protection() -> TestResult {
    if vectors::VECTOR_GENERAL_PROTECTION != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_page_fault() -> TestResult {
    if vectors::VECTOR_PAGE_FAULT != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_x87_fp() -> TestResult {
    if vectors::VECTOR_X87_FLOATING_POINT != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_alignment_check() -> TestResult {
    if vectors::VECTOR_ALIGNMENT_CHECK != 17 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_machine_check() -> TestResult {
    if vectors::VECTOR_MACHINE_CHECK != 18 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_simd_fp() -> TestResult {
    if vectors::VECTOR_SIMD_FLOATING_POINT != 19 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_virtualization() -> TestResult {
    if vectors::VECTOR_VIRTUALIZATION != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_timer() -> TestResult {
    if vectors::VECTOR_TIMER != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_keyboard() -> TestResult {
    if vectors::VECTOR_KEYBOARD != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_mouse() -> TestResult {
    if vectors::VECTOR_MOUSE != 44 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_syscall() -> TestResult {
    if vectors::VECTOR_SYSCALL != 0x80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_apic_spurious() -> TestResult {
    if vectors::VECTOR_APIC_SPURIOUS != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_constants_apic_error() -> TestResult {
    if vectors::VECTOR_APIC_ERROR != 0xFE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_vector_range() -> TestResult {
    if vectors::EXCEPTION_VECTOR_START != 0 {
        return TestResult::Fail;
    }
    if vectors::EXCEPTION_VECTOR_END != 31 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_vector_range() -> TestResult {
    if vectors::IRQ_VECTOR_START != 32 {
        return TestResult::Fail;
    }
    if vectors::IRQ_VECTOR_END != 47 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_user_vector_range() -> TestResult {
    if vectors::USER_VECTOR_START != 48 {
        return TestResult::Fail;
    }
    if vectors::USER_VECTOR_END != 0xEF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_exception() -> TestResult {
    if !is_exception(0) {
        return TestResult::Fail;
    }
    if !is_exception(14) {
        return TestResult::Fail;
    }
    if !is_exception(31) {
        return TestResult::Fail;
    }
    if is_exception(32) {
        return TestResult::Fail;
    }
    if is_exception(128) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_irq() -> TestResult {
    if is_irq(31) {
        return TestResult::Fail;
    }
    if !is_irq(32) {
        return TestResult::Fail;
    }
    if !is_irq(47) {
        return TestResult::Fail;
    }
    if is_irq(48) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_user_allocatable() -> TestResult {
    if is_user_allocatable(31) {
        return TestResult::Fail;
    }
    if is_user_allocatable(32) {
        return TestResult::Fail;
    }
    if is_user_allocatable(47) {
        return TestResult::Fail;
    }
    if !is_user_allocatable(48) {
        return TestResult::Fail;
    }
    if !is_user_allocatable(0xEF) {
        return TestResult::Fail;
    }
    if is_user_allocatable(0xF0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_irq_to_vector() -> TestResult {
    if irq_to_vector(0) != 32 {
        return TestResult::Fail;
    }
    if irq_to_vector(1) != 33 {
        return TestResult::Fail;
    }
    if irq_to_vector(15) != 47 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_to_irq_valid() -> TestResult {
    if vector_to_irq(32) != Some(0) {
        return TestResult::Fail;
    }
    if vector_to_irq(33) != Some(1) {
        return TestResult::Fail;
    }
    if vector_to_irq(47) != Some(15) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vector_to_irq_invalid() -> TestResult {
    if vector_to_irq(0) != None {
        return TestResult::Fail;
    }
    if vector_to_irq(31) != None {
        return TestResult::Fail;
    }
    if vector_to_irq(48) != None {
        return TestResult::Fail;
    }
    if vector_to_irq(128) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_divide_error() -> TestResult {
    if exception_name(0) != "Divide Error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_debug() -> TestResult {
    if exception_name(1) != "Debug" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_nmi() -> TestResult {
    if exception_name(2) != "Non-Maskable Interrupt" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_breakpoint() -> TestResult {
    if exception_name(3) != "Breakpoint" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_page_fault() -> TestResult {
    if exception_name(14) != "Page Fault" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_double_fault() -> TestResult {
    if exception_name(8) != "Double Fault" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_gpf() -> TestResult {
    if exception_name(13) != "General Protection Fault" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_name_reserved() -> TestResult {
    if exception_name(15) != "Reserved" {
        return TestResult::Fail;
    }
    if exception_name(22) != "Reserved" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_double_fault() -> TestResult {
    if !exception_has_error_code(8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_invalid_tss() -> TestResult {
    if !exception_has_error_code(10) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_segment_not_present() -> TestResult {
    if !exception_has_error_code(11) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_stack_segment() -> TestResult {
    if !exception_has_error_code(12) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_gpf() -> TestResult {
    if !exception_has_error_code(13) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_page_fault() -> TestResult {
    if !exception_has_error_code(14) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_error_code_alignment_check() -> TestResult {
    if !exception_has_error_code(17) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_no_error_code_divide() -> TestResult {
    if exception_has_error_code(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_no_error_code_debug() -> TestResult {
    if exception_has_error_code(1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_has_no_error_code_breakpoint() -> TestResult {
    if exception_has_error_code(3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_is_fatal_divide() -> TestResult {
    if !exception_is_fatal(0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_is_fatal_invalid_opcode() -> TestResult {
    if !exception_is_fatal(6) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_is_fatal_double_fault() -> TestResult {
    if !exception_is_fatal(8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_is_fatal_gpf() -> TestResult {
    if !exception_is_fatal(13) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_is_fatal_machine_check() -> TestResult {
    if !exception_is_fatal(18) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_not_fatal_page_fault() -> TestResult {
    if exception_is_fatal(14) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_not_fatal_debug() -> TestResult {
    if exception_is_fatal(1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_exception_not_fatal_breakpoint() -> TestResult {
    if exception_is_fatal(3) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
