// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Observability and output mode tests

extern crate alloc;

use crate::security::*;
use crate::test::framework::TestResult;
use alloc::format;

pub(crate) fn test_output_mode_minimal() -> TestResult {
    let mode = OutputMode::Minimal;
    if mode as u8 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_standard() -> TestResult {
    let mode = OutputMode::Standard;
    if mode as u8 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_verbose() -> TestResult {
    let mode = OutputMode::Verbose;
    if mode as u8 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_debug() -> TestResult {
    let mode = OutputMode::Debug;
    if mode as u8 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_from_u8_minimal() -> TestResult {
    let mode: OutputMode = 0u8.into();
    if mode != OutputMode::Minimal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_from_u8_standard() -> TestResult {
    let mode: OutputMode = 1u8.into();
    if mode != OutputMode::Standard {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_from_u8_verbose() -> TestResult {
    let mode: OutputMode = 2u8.into();
    if mode != OutputMode::Verbose {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_from_u8_debug() -> TestResult {
    let mode: OutputMode = 3u8.into();
    if mode != OutputMode::Debug {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_from_u8_invalid() -> TestResult {
    let mode: OutputMode = 100u8.into();
    if mode != OutputMode::Minimal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_equality() -> TestResult {
    if OutputMode::Minimal != OutputMode::Minimal {
        return TestResult::Fail;
    }
    if OutputMode::Minimal == OutputMode::Debug {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_copy() -> TestResult {
    let mode1 = OutputMode::Verbose;
    let mode2 = mode1;
    if mode1 != mode2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_observability_policy_default() -> TestResult {
    let policy = ObservabilityPolicy::default();
    if !policy.production {
        return TestResult::Fail;
    }
    if policy.output_mode != OutputMode::Minimal {
        return TestResult::Fail;
    }
    if policy.serial_enabled {
        return TestResult::Fail;
    }
    if !policy.vga_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_observability_policy_custom() -> TestResult {
    let policy = ObservabilityPolicy {
        production: false,
        output_mode: OutputMode::Debug,
        serial_enabled: true,
        vga_enabled: false,
    };
    if policy.production {
        return TestResult::Fail;
    }
    if policy.output_mode != OutputMode::Debug {
        return TestResult::Fail;
    }
    if !policy.serial_enabled {
        return TestResult::Fail;
    }
    if policy.vga_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_observability_policy_copy() -> TestResult {
    let policy1 = ObservabilityPolicy::default();
    let policy2 = policy1;
    if policy1.production != policy2.production {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_production_mode() -> TestResult {
    let result = is_production_mode();
    let _ = result;
    TestResult::Pass
}

pub(crate) fn test_set_production_mode_true() -> TestResult {
    set_production_mode(true);
    if !is_production_mode() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_production_mode_false() -> TestResult {
    set_production_mode(false);
    if is_production_mode() {
        return TestResult::Fail;
    }
    set_production_mode(true);
    TestResult::Pass
}

pub(crate) fn test_should_log_debug_production() -> TestResult {
    set_production_mode(true);
    if should_log_debug() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_should_emit_serial() -> TestResult {
    let result = should_emit_serial();
    let _ = result;
    TestResult::Pass
}

pub(crate) fn test_redact_pointer_production() -> TestResult {
    set_production_mode(true);
    let result = redact_pointer(0xDEADBEEF);
    if result != "[REDACTED]" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_pointer_development() -> TestResult {
    set_production_mode(false);
    let result = redact_pointer(0x12345678);
    if !result.contains("0x") {
        return TestResult::Fail;
    }
    set_production_mode(true);
    TestResult::Pass
}

pub(crate) fn test_redact_address_production() -> TestResult {
    set_production_mode(true);
    let result = redact_address(0xCAFEBABE);
    if result != "[ADDR]" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_address_development() -> TestResult {
    set_production_mode(false);
    let result = redact_address(0x87654321);
    if !result.contains("0x") {
        return TestResult::Fail;
    }
    set_production_mode(true);
    TestResult::Pass
}

pub(crate) fn test_redact_panic_message_production() -> TestResult {
    set_production_mode(true);
    let result = redact_panic_message("Error at /src/file.rs:42");
    if result.contains("/src/file.rs") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_panic_message_development() -> TestResult {
    set_production_mode(false);
    let msg = "Error at /src/file.rs:42";
    let result = redact_panic_message(msg);
    if result != msg {
        return TestResult::Fail;
    }
    set_production_mode(true);
    TestResult::Pass
}

pub(crate) fn test_redact_panic_message_with_address() -> TestResult {
    set_production_mode(true);
    let result = redact_panic_message("Crash at 0xDEADBEEF");
    if !result.contains("[ADDR]") && result.contains("0xDEADBEEF") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_observability_policy_debug_format() -> TestResult {
    let policy = ObservabilityPolicy::default();
    let debug_str = format!("{:?}", policy);
    if !debug_str.contains("ObservabilityPolicy") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_debug_format() -> TestResult {
    let mode = OutputMode::Verbose;
    let debug_str = format!("{:?}", mode);
    if !debug_str.contains("Verbose") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_output_modes() -> TestResult {
    let modes = [OutputMode::Minimal, OutputMode::Standard, OutputMode::Verbose, OutputMode::Debug];
    if modes.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_output_mode_ordering() -> TestResult {
    if (OutputMode::Minimal as u8) >= (OutputMode::Standard as u8) {
        return TestResult::Fail;
    }
    if (OutputMode::Standard as u8) >= (OutputMode::Verbose as u8) {
        return TestResult::Fail;
    }
    if (OutputMode::Verbose as u8) >= (OutputMode::Debug as u8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_pointer_zero() -> TestResult {
    set_production_mode(true);
    let result = redact_pointer(0);
    if result != "[REDACTED]" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_address_zero() -> TestResult {
    set_production_mode(true);
    let result = redact_address(0);
    if result != "[ADDR]" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_pointer_max() -> TestResult {
    set_production_mode(true);
    let result = redact_pointer(usize::MAX);
    if result != "[REDACTED]" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_address_max() -> TestResult {
    set_production_mode(true);
    let result = redact_address(u64::MAX);
    if result != "[ADDR]" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_panic_message_empty() -> TestResult {
    set_production_mode(true);
    let result = redact_panic_message("");
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_redact_panic_message_no_sensitive_data() -> TestResult {
    set_production_mode(true);
    let msg = "Simple error message";
    let result = redact_panic_message(msg);
    if !result.contains("Simple error message") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_production_mode_toggle() -> TestResult {
    let original = is_production_mode();
    set_production_mode(!original);
    if is_production_mode() == original {
        return TestResult::Fail;
    }
    set_production_mode(original);
    if is_production_mode() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_observability_policy_all_disabled() -> TestResult {
    let policy = ObservabilityPolicy {
        production: false,
        output_mode: OutputMode::Minimal,
        serial_enabled: false,
        vga_enabled: false,
    };
    if policy.serial_enabled {
        return TestResult::Fail;
    }
    if policy.vga_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_observability_policy_all_enabled() -> TestResult {
    let policy = ObservabilityPolicy {
        production: true,
        output_mode: OutputMode::Debug,
        serial_enabled: true,
        vga_enabled: true,
    };
    if !policy.serial_enabled {
        return TestResult::Fail;
    }
    if !policy.vga_enabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serial_log() -> TestResult {
    serial_log("Test log message");
    TestResult::Pass
}

pub(crate) fn test_serial_log_redacted() -> TestResult {
    serial_log_redacted("Test redacted message");
    TestResult::Pass
}
