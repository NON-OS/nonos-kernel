// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// XHCI driver test suite - 36 tests across 6 modules

pub mod constants_tests;
pub mod context;
pub mod error;
pub mod stats;
pub mod trb;
pub mod types_tests;

use crate::test::framework::{TestCase, TestSuite};

/// Run all XHCI driver tests.
/// Returns true if all tests pass.
pub fn run_all() -> bool {
    let mut suite = TestSuite::new("XHCI Driver");

    // Constants tests - 4 tests
    suite.add(TestCase::with_category(
        "portsc_change_bits",
        constants_tests::test_portsc_change_bits,
        "drivers/xhci/constants",
    ));
    suite.add(TestCase::with_category(
        "trb_alignment_constant",
        constants_tests::test_trb_alignment_constant,
        "drivers/xhci/constants",
    ));
    suite.add(TestCase::with_category(
        "ring_size_constants",
        constants_tests::test_ring_size_constants,
        "drivers/xhci/constants",
    ));
    suite.add(TestCase::with_category(
        "valid_trb_types_lists",
        constants_tests::test_valid_trb_types_lists,
        "drivers/xhci/constants",
    ));

    // Context tests - 8 tests
    suite.add(TestCase::with_category(
        "slot_context_size",
        context::test_slot_context_size,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "ep_context_size",
        context::test_ep_context_size,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "device_context_alignment",
        context::test_device_context_alignment,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "slot_context_fields",
        context::test_slot_context_fields,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "ep_context_dequeue_pointer",
        context::test_ep_context_dequeue_pointer,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "ep_context_max_packet_size",
        context::test_ep_context_max_packet_size,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "ep_addr_to_dci",
        context::test_ep_addr_to_dci,
        "drivers/xhci/context",
    ));
    suite.add(TestCase::with_category(
        "input_control_context",
        context::test_input_control_context,
        "drivers/xhci/context",
    ));

    // Error tests - 5 tests
    suite.add(TestCase::with_category(
        "error_display",
        error::test_error_display,
        "drivers/xhci/error",
    ));
    suite.add(TestCase::with_category(
        "completion_code_extraction",
        error::test_completion_code_extraction,
        "drivers/xhci/error",
    ));
    suite.add(TestCase::with_category(
        "error_requires_reset",
        error::test_error_requires_reset,
        "drivers/xhci/error",
    ));
    suite.add(TestCase::with_category(
        "error_is_recoverable",
        error::test_error_is_recoverable,
        "drivers/xhci/error",
    ));
    suite.add(TestCase::with_category(
        "from_completion_code",
        error::test_from_completion_code,
        "drivers/xhci/error",
    ));

    // Stats tests - 4 tests
    suite.add(TestCase::with_category(
        "stats_increment",
        stats::test_stats_increment,
        "drivers/xhci/stats",
    ));
    suite.add(TestCase::with_category(
        "stats_total_errors",
        stats::test_stats_total_errors,
        "drivers/xhci/stats",
    ));
    suite.add(TestCase::with_category(
        "stats_error_rate",
        stats::test_stats_error_rate,
        "drivers/xhci/stats",
    ));
    suite.add(TestCase::with_category(
        "controller_health",
        stats::test_controller_health,
        "drivers/xhci/stats",
    ));

    // TRB tests - 12 tests
    suite.add(TestCase::with_category(
        "trb_size_and_alignment",
        trb::test_trb_size_and_alignment,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "trb_type_field",
        trb::test_trb_type_field,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "trb_cycle_bit",
        trb::test_trb_cycle_bit,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category("trb_pointer", trb::test_trb_pointer, "drivers/xhci/trb"));
    suite.add(TestCase::with_category("trb_ioc_bit", trb::test_trb_ioc_bit, "drivers/xhci/trb"));
    suite.add(TestCase::with_category(
        "trb_pointer_alignment_validation",
        trb::test_trb_pointer_alignment_validation,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "setup_stage_builder",
        trb::test_setup_stage_builder,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "data_stage_builder",
        trb::test_data_stage_builder,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "status_stage_builder",
        trb::test_status_stage_builder,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "link_trb_builder",
        trb::test_link_trb_builder,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "enable_slot_command",
        trb::test_enable_slot_command,
        "drivers/xhci/trb",
    ));
    suite.add(TestCase::with_category(
        "address_device_command",
        trb::test_address_device_command,
        "drivers/xhci/trb",
    ));

    // Types tests - 3 tests
    suite.add(TestCase::with_category(
        "usb_device_descriptor_size",
        types_tests::test_usb_device_descriptor_size,
        "drivers/xhci/types",
    ));
    suite.add(TestCase::with_category(
        "usb_device_descriptor_validation",
        types_tests::test_usb_device_descriptor_validation,
        "drivers/xhci/types",
    ));
    suite.add(TestCase::with_category(
        "usb_version_parsing",
        types_tests::test_usb_version_parsing,
        "drivers/xhci/types",
    ));

    let (_, failed, _) = suite.run_all();
    failed == 0
}
