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

pub mod allocation;
pub mod apic;
pub mod counters;
pub mod idt;
pub mod pic;
pub mod safety;

use crate::test::framework::{TestCase, TestSuite};

pub fn run_all() -> bool {
    let mut suite = TestSuite::new("interrupts");

    // Allocation tests (21)
    suite.add(TestCase::new("vector_count", allocation::test_vector_count));
    suite.add(TestCase::new("reserved_vectors_end", allocation::test_reserved_vectors_end));
    suite.add(TestCase::new("timer_vector", allocation::test_timer_vector));
    suite.add(TestCase::new("keyboard_vector", allocation::test_keyboard_vector));
    suite.add(TestCase::new("syscall_vector", allocation::test_syscall_vector));
    suite.add(TestCase::new(
        "reserved_vectors_below_32",
        allocation::test_reserved_vectors_below_32,
    ));
    suite.add(TestCase::new(
        "is_vector_available_checks_reserved",
        allocation::test_is_vector_available_checks_reserved,
    ));
    suite.add(TestCase::new(
        "allocate_vector_returns_above_reserved",
        allocation::test_allocate_vector_returns_above_reserved,
    ));
    suite.add(TestCase::new("allocate_and_free_vector", allocation::test_allocate_and_free_vector));
    suite.add(TestCase::new(
        "free_reserved_vector_fails",
        allocation::test_free_reserved_vector_fails,
    ));
    suite.add(TestCase::new(
        "free_reserved_vector_31_fails",
        allocation::test_free_reserved_vector_31_fails,
    ));
    suite.add(TestCase::new(
        "free_unallocated_vector_fails",
        allocation::test_free_unallocated_vector_fails,
    ));
    suite.add(TestCase::new(
        "register_handler_reserved_fails",
        allocation::test_register_handler_reserved_fails,
    ));
    suite.add(TestCase::new(
        "register_handler_reserved_31_fails",
        allocation::test_register_handler_reserved_31_fails,
    ));
    suite.add(TestCase::new(
        "unregister_handler_reserved_fails",
        allocation::test_unregister_handler_reserved_fails,
    ));
    suite.add(TestCase::new(
        "unregister_handler_reserved_31_fails",
        allocation::test_unregister_handler_reserved_31_fails,
    ));
    suite.add(TestCase::new(
        "get_handler_none_for_unregistered",
        allocation::test_get_handler_none_for_unregistered,
    ));
    suite.add(TestCase::new("register_and_get_handler", allocation::test_register_and_get_handler));
    suite.add(TestCase::new(
        "register_handler_twice_fails",
        allocation::test_register_handler_twice_fails,
    ));
    suite.add(TestCase::new(
        "unregister_and_register_handler",
        allocation::test_unregister_and_register_handler,
    ));
    suite.add(TestCase::new(
        "unregister_handler_none_fails",
        allocation::test_unregister_handler_none_fails,
    ));
    suite.add(TestCase::new("registry_exists", allocation::test_registry_exists));
    suite.add(TestCase::new("multiple_allocations", allocation::test_multiple_allocations));

    // APIC tests (2)
    suite.add(TestCase::new(
        "apic_is_enabled_returns_bool",
        apic::test_apic_is_enabled_returns_bool,
    ));
    suite.add(TestCase::new("apic_is_enabled_consistent", apic::test_apic_is_enabled_consistent));

    // Counters tests (13)
    suite.add(TestCase::new("interrupt_counters_new", counters::test_interrupt_counters_new));
    suite.add(TestCase::new(
        "counters_static_initialization",
        counters::test_counters_static_initialization,
    ));
    suite.add(TestCase::new("increment_timer", counters::test_increment_timer));
    suite.add(TestCase::new("increment_keyboard", counters::test_increment_keyboard));
    suite.add(TestCase::new("increment_mouse", counters::test_increment_mouse));
    suite.add(TestCase::new("increment_syscalls", counters::test_increment_syscalls));
    suite.add(TestCase::new("increment_exceptions", counters::test_increment_exceptions));
    suite.add(TestCase::new("increment_page_faults", counters::test_increment_page_faults));
    suite.add(TestCase::new("get_stats_returns_struct", counters::test_get_stats_returns_struct));
    suite.add(TestCase::new(
        "get_stats_tuple_returns_four_values",
        counters::test_get_stats_tuple_returns_four_values,
    ));
    suite.add(TestCase::new("reset_stats", counters::test_reset_stats));
    suite.add(TestCase::new("interrupt_stats_fields", counters::test_interrupt_stats_fields));
    suite.add(TestCase::new("multiple_increments", counters::test_multiple_increments));

    // IDT tests (63)
    suite.add(TestCase::new("timer_interrupt_id", idt::test_timer_interrupt_id));
    suite.add(TestCase::new("keyboard_interrupt_id", idt::test_keyboard_interrupt_id));
    suite.add(TestCase::new("mouse_interrupt_id", idt::test_mouse_interrupt_id));
    suite.add(TestCase::new("syscall_interrupt_id", idt::test_syscall_interrupt_id));
    suite.add(TestCase::new("double_fault_ist_index", idt::test_double_fault_ist_index));
    suite.add(TestCase::new("page_fault_ist_index", idt::test_page_fault_ist_index));
    suite.add(TestCase::new("nmi_ist_index", idt::test_nmi_ist_index));
    suite.add(TestCase::new("machine_check_ist_index", idt::test_machine_check_ist_index));
    suite.add(TestCase::new("gate_type_interrupt_value", idt::test_gate_type_interrupt_value));
    suite.add(TestCase::new("gate_type_trap_value", idt::test_gate_type_trap_value));
    suite.add(TestCase::new("entry_options_new", idt::test_entry_options_new));
    suite.add(TestCase::new("entry_options_interrupt", idt::test_entry_options_interrupt));
    suite.add(TestCase::new("entry_options_trap", idt::test_entry_options_trap));
    suite.add(TestCase::new(
        "entry_options_with_privilege_level",
        idt::test_entry_options_with_privilege_level,
    ));
    suite
        .add(TestCase::new("entry_options_with_ist_index", idt::test_entry_options_with_ist_index));
    suite.add(TestCase::new("entry_options_user_callable", idt::test_entry_options_user_callable));
    suite.add(TestCase::new("entry_options_default", idt::test_entry_options_default));
    suite.add(TestCase::new(
        "entry_error_invalid_ist_index_str",
        idt::test_entry_error_invalid_ist_index_str,
    ));
    suite.add(TestCase::new(
        "entry_error_handler_not_present_str",
        idt::test_entry_error_handler_not_present_str,
    ));
    suite.add(TestCase::new("validate_ist_index_valid", idt::test_validate_ist_index_valid));
    suite.add(TestCase::new("validate_ist_index_invalid", idt::test_validate_ist_index_invalid));
    suite.add(TestCase::new(
        "validate_handler_address_valid",
        idt::test_validate_handler_address_valid,
    ));
    suite.add(TestCase::new(
        "validate_handler_address_null",
        idt::test_validate_handler_address_null,
    ));
    suite.add(TestCase::new(
        "vector_constants_divide_error",
        idt::test_vector_constants_divide_error,
    ));
    suite.add(TestCase::new("vector_constants_debug", idt::test_vector_constants_debug));
    suite.add(TestCase::new("vector_constants_nmi", idt::test_vector_constants_nmi));
    suite.add(TestCase::new("vector_constants_breakpoint", idt::test_vector_constants_breakpoint));
    suite.add(TestCase::new("vector_constants_overflow", idt::test_vector_constants_overflow));
    suite
        .add(TestCase::new("vector_constants_bound_range", idt::test_vector_constants_bound_range));
    suite.add(TestCase::new(
        "vector_constants_invalid_opcode",
        idt::test_vector_constants_invalid_opcode,
    ));
    suite.add(TestCase::new(
        "vector_constants_device_not_available",
        idt::test_vector_constants_device_not_available,
    ));
    suite.add(TestCase::new(
        "vector_constants_double_fault",
        idt::test_vector_constants_double_fault,
    ));
    suite
        .add(TestCase::new("vector_constants_invalid_tss", idt::test_vector_constants_invalid_tss));
    suite.add(TestCase::new(
        "vector_constants_segment_not_present",
        idt::test_vector_constants_segment_not_present,
    ));
    suite.add(TestCase::new(
        "vector_constants_stack_segment_fault",
        idt::test_vector_constants_stack_segment_fault,
    ));
    suite.add(TestCase::new(
        "vector_constants_general_protection",
        idt::test_vector_constants_general_protection,
    ));
    suite.add(TestCase::new("vector_constants_page_fault", idt::test_vector_constants_page_fault));
    suite.add(TestCase::new("vector_constants_x87_fp", idt::test_vector_constants_x87_fp));
    suite.add(TestCase::new(
        "vector_constants_alignment_check",
        idt::test_vector_constants_alignment_check,
    ));
    suite.add(TestCase::new(
        "vector_constants_machine_check",
        idt::test_vector_constants_machine_check,
    ));
    suite.add(TestCase::new("vector_constants_simd_fp", idt::test_vector_constants_simd_fp));
    suite.add(TestCase::new(
        "vector_constants_virtualization",
        idt::test_vector_constants_virtualization,
    ));
    suite.add(TestCase::new("vector_constants_timer", idt::test_vector_constants_timer));
    suite.add(TestCase::new("vector_constants_keyboard", idt::test_vector_constants_keyboard));
    suite.add(TestCase::new("vector_constants_mouse", idt::test_vector_constants_mouse));
    suite.add(TestCase::new("vector_constants_syscall", idt::test_vector_constants_syscall));
    suite.add(TestCase::new(
        "vector_constants_apic_spurious",
        idt::test_vector_constants_apic_spurious,
    ));
    suite.add(TestCase::new("vector_constants_apic_error", idt::test_vector_constants_apic_error));
    suite.add(TestCase::new("exception_vector_range", idt::test_exception_vector_range));
    suite.add(TestCase::new("irq_vector_range", idt::test_irq_vector_range));
    suite.add(TestCase::new("user_vector_range", idt::test_user_vector_range));
    suite.add(TestCase::new("is_exception", idt::test_is_exception));
    suite.add(TestCase::new("is_irq", idt::test_is_irq));
    suite.add(TestCase::new("is_user_allocatable", idt::test_is_user_allocatable));
    suite.add(TestCase::new("irq_to_vector", idt::test_irq_to_vector));
    suite.add(TestCase::new("vector_to_irq_valid", idt::test_vector_to_irq_valid));
    suite.add(TestCase::new("vector_to_irq_invalid", idt::test_vector_to_irq_invalid));
    suite.add(TestCase::new("exception_name_divide_error", idt::test_exception_name_divide_error));
    suite.add(TestCase::new("exception_name_debug", idt::test_exception_name_debug));
    suite.add(TestCase::new("exception_name_nmi", idt::test_exception_name_nmi));
    suite.add(TestCase::new("exception_name_breakpoint", idt::test_exception_name_breakpoint));
    suite.add(TestCase::new("exception_name_page_fault", idt::test_exception_name_page_fault));
    suite.add(TestCase::new("exception_name_double_fault", idt::test_exception_name_double_fault));
    suite.add(TestCase::new("exception_name_gpf", idt::test_exception_name_gpf));
    suite.add(TestCase::new("exception_name_reserved", idt::test_exception_name_reserved));
    suite.add(TestCase::new(
        "exception_has_error_code_double_fault",
        idt::test_exception_has_error_code_double_fault,
    ));
    suite.add(TestCase::new(
        "exception_has_error_code_invalid_tss",
        idt::test_exception_has_error_code_invalid_tss,
    ));
    suite.add(TestCase::new(
        "exception_has_error_code_segment_not_present",
        idt::test_exception_has_error_code_segment_not_present,
    ));
    suite.add(TestCase::new(
        "exception_has_error_code_stack_segment",
        idt::test_exception_has_error_code_stack_segment,
    ));
    suite
        .add(TestCase::new("exception_has_error_code_gpf", idt::test_exception_has_error_code_gpf));
    suite.add(TestCase::new(
        "exception_has_error_code_page_fault",
        idt::test_exception_has_error_code_page_fault,
    ));
    suite.add(TestCase::new(
        "exception_has_error_code_alignment_check",
        idt::test_exception_has_error_code_alignment_check,
    ));
    suite.add(TestCase::new(
        "exception_has_no_error_code_divide",
        idt::test_exception_has_no_error_code_divide,
    ));
    suite.add(TestCase::new(
        "exception_has_no_error_code_debug",
        idt::test_exception_has_no_error_code_debug,
    ));
    suite.add(TestCase::new(
        "exception_has_no_error_code_breakpoint",
        idt::test_exception_has_no_error_code_breakpoint,
    ));
    suite.add(TestCase::new("exception_is_fatal_divide", idt::test_exception_is_fatal_divide));
    suite.add(TestCase::new(
        "exception_is_fatal_invalid_opcode",
        idt::test_exception_is_fatal_invalid_opcode,
    ));
    suite.add(TestCase::new(
        "exception_is_fatal_double_fault",
        idt::test_exception_is_fatal_double_fault,
    ));
    suite.add(TestCase::new("exception_is_fatal_gpf", idt::test_exception_is_fatal_gpf));
    suite.add(TestCase::new(
        "exception_is_fatal_machine_check",
        idt::test_exception_is_fatal_machine_check,
    ));
    suite.add(TestCase::new(
        "exception_not_fatal_page_fault",
        idt::test_exception_not_fatal_page_fault,
    ));
    suite.add(TestCase::new("exception_not_fatal_debug", idt::test_exception_not_fatal_debug));
    suite.add(TestCase::new(
        "exception_not_fatal_breakpoint",
        idt::test_exception_not_fatal_breakpoint,
    ));

    // PIC tests (3)
    suite.add(TestCase::new("module_exists", pic::test_module_exists));
    suite.add(TestCase::new("basic_constants", pic::test_basic_constants));
    suite.add(TestCase::new("basic_operations", pic::test_basic_operations));

    // Safety tests (9)
    suite.add(TestCase::new(
        "in_interrupt_context_returns_bool",
        safety::test_in_interrupt_context_returns_bool,
    ));
    suite.add(TestCase::new(
        "set_interrupt_context_creates_context",
        safety::test_set_interrupt_context_creates_context,
    ));
    suite.add(TestCase::new(
        "interrupt_context_cleared_on_drop",
        safety::test_interrupt_context_cleared_on_drop,
    ));
    suite.add(TestCase::new("nested_interrupt_context", safety::test_nested_interrupt_context));
    suite.add(TestCase::new(
        "disable_interrupts_guard_returns_guard",
        safety::test_disable_interrupts_guard_returns_guard,
    ));
    suite.add(TestCase::new(
        "interrupt_guard_restores_on_drop",
        safety::test_interrupt_guard_restores_on_drop,
    ));
    suite.add(TestCase::new("nested_interrupt_guards", safety::test_nested_interrupt_guards));
    suite.add(TestCase::new(
        "interrupt_context_multiple_drops",
        safety::test_interrupt_context_multiple_drops,
    ));
    suite.add(TestCase::new(
        "interrupt_guard_and_context_together",
        safety::test_interrupt_guard_and_context_together,
    ));

    suite.run()
}
