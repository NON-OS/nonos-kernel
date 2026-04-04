use crate::security::*;

#[test]
fn test_output_mode_minimal() {
    let mode = OutputMode::Minimal;
    assert_eq!(mode as u8, 0);
}

#[test]
fn test_output_mode_standard() {
    let mode = OutputMode::Standard;
    assert_eq!(mode as u8, 1);
}

#[test]
fn test_output_mode_verbose() {
    let mode = OutputMode::Verbose;
    assert_eq!(mode as u8, 2);
}

#[test]
fn test_output_mode_debug() {
    let mode = OutputMode::Debug;
    assert_eq!(mode as u8, 3);
}

#[test]
fn test_output_mode_from_u8_minimal() {
    let mode: OutputMode = 0u8.into();
    assert_eq!(mode, OutputMode::Minimal);
}

#[test]
fn test_output_mode_from_u8_standard() {
    let mode: OutputMode = 1u8.into();
    assert_eq!(mode, OutputMode::Standard);
}

#[test]
fn test_output_mode_from_u8_verbose() {
    let mode: OutputMode = 2u8.into();
    assert_eq!(mode, OutputMode::Verbose);
}

#[test]
fn test_output_mode_from_u8_debug() {
    let mode: OutputMode = 3u8.into();
    assert_eq!(mode, OutputMode::Debug);
}

#[test]
fn test_output_mode_from_u8_invalid() {
    let mode: OutputMode = 100u8.into();
    assert_eq!(mode, OutputMode::Minimal);
}

#[test]
fn test_output_mode_equality() {
    assert_eq!(OutputMode::Minimal, OutputMode::Minimal);
    assert_ne!(OutputMode::Minimal, OutputMode::Debug);
}

#[test]
fn test_output_mode_copy() {
    let mode1 = OutputMode::Verbose;
    let mode2 = mode1;
    assert_eq!(mode1, mode2);
}

#[test]
fn test_observability_policy_default() {
    let policy = ObservabilityPolicy::default();
    assert!(policy.production);
    assert_eq!(policy.output_mode, OutputMode::Minimal);
    assert!(!policy.serial_enabled);
    assert!(policy.vga_enabled);
}

#[test]
fn test_observability_policy_custom() {
    let policy = ObservabilityPolicy {
        production: false,
        output_mode: OutputMode::Debug,
        serial_enabled: true,
        vga_enabled: false,
    };
    assert!(!policy.production);
    assert_eq!(policy.output_mode, OutputMode::Debug);
    assert!(policy.serial_enabled);
    assert!(!policy.vga_enabled);
}

#[test]
fn test_observability_policy_copy() {
    let policy1 = ObservabilityPolicy::default();
    let policy2 = policy1;
    assert_eq!(policy1.production, policy2.production);
}

#[test]
fn test_is_production_mode() {
    let result = is_production_mode();
    let _ = result;
}

#[test]
fn test_set_production_mode_true() {
    set_production_mode(true);
    assert!(is_production_mode());
}

#[test]
fn test_set_production_mode_false() {
    set_production_mode(false);
    assert!(!is_production_mode());
    set_production_mode(true);
}

#[test]
fn test_should_log_debug_production() {
    set_production_mode(true);
    assert!(!should_log_debug());
}

#[test]
fn test_should_emit_serial() {
    let result = should_emit_serial();
    let _ = result;
}

#[test]
fn test_redact_pointer_production() {
    set_production_mode(true);
    let result = redact_pointer(0xDEADBEEF);
    assert_eq!(result, "[REDACTED]");
}

#[test]
fn test_redact_pointer_development() {
    set_production_mode(false);
    let result = redact_pointer(0x12345678);
    assert!(result.contains("0x"));
    set_production_mode(true);
}

#[test]
fn test_redact_address_production() {
    set_production_mode(true);
    let result = redact_address(0xCAFEBABE);
    assert_eq!(result, "[ADDR]");
}

#[test]
fn test_redact_address_development() {
    set_production_mode(false);
    let result = redact_address(0x87654321);
    assert!(result.contains("0x"));
    set_production_mode(true);
}

#[test]
fn test_redact_panic_message_production() {
    set_production_mode(true);
    let result = redact_panic_message("Error at /src/file.rs:42");
    assert!(!result.contains("/src/file.rs"));
}

#[test]
fn test_redact_panic_message_development() {
    set_production_mode(false);
    let msg = "Error at /src/file.rs:42";
    let result = redact_panic_message(msg);
    assert_eq!(result, msg);
    set_production_mode(true);
}

#[test]
fn test_redact_panic_message_with_address() {
    set_production_mode(true);
    let result = redact_panic_message("Crash at 0xDEADBEEF");
    assert!(result.contains("[ADDR]") || !result.contains("0xDEADBEEF"));
}

#[test]
fn test_observability_policy_debug_format() {
    let policy = ObservabilityPolicy::default();
    let debug_str = alloc::format!("{:?}", policy);
    assert!(debug_str.contains("ObservabilityPolicy"));
}

#[test]
fn test_output_mode_debug_format() {
    let mode = OutputMode::Verbose;
    let debug_str = alloc::format!("{:?}", mode);
    assert!(debug_str.contains("Verbose"));
}

#[test]
fn test_all_output_modes() {
    let modes = [
        OutputMode::Minimal,
        OutputMode::Standard,
        OutputMode::Verbose,
        OutputMode::Debug,
    ];
    assert_eq!(modes.len(), 4);
}

#[test]
fn test_output_mode_ordering() {
    assert!((OutputMode::Minimal as u8) < (OutputMode::Standard as u8));
    assert!((OutputMode::Standard as u8) < (OutputMode::Verbose as u8));
    assert!((OutputMode::Verbose as u8) < (OutputMode::Debug as u8));
}

#[test]
fn test_redact_pointer_zero() {
    set_production_mode(true);
    let result = redact_pointer(0);
    assert_eq!(result, "[REDACTED]");
}

#[test]
fn test_redact_address_zero() {
    set_production_mode(true);
    let result = redact_address(0);
    assert_eq!(result, "[ADDR]");
}

#[test]
fn test_redact_pointer_max() {
    set_production_mode(true);
    let result = redact_pointer(usize::MAX);
    assert_eq!(result, "[REDACTED]");
}

#[test]
fn test_redact_address_max() {
    set_production_mode(true);
    let result = redact_address(u64::MAX);
    assert_eq!(result, "[ADDR]");
}

#[test]
fn test_redact_panic_message_empty() {
    set_production_mode(true);
    let result = redact_panic_message("");
    assert!(result.is_empty());
}

#[test]
fn test_redact_panic_message_no_sensitive_data() {
    set_production_mode(true);
    let msg = "Simple error message";
    let result = redact_panic_message(msg);
    assert!(result.contains("Simple error message"));
}

#[test]
fn test_production_mode_toggle() {
    let original = is_production_mode();
    set_production_mode(!original);
    assert_ne!(is_production_mode(), original);
    set_production_mode(original);
    assert_eq!(is_production_mode(), original);
}

#[test]
fn test_observability_policy_all_disabled() {
    let policy = ObservabilityPolicy {
        production: false,
        output_mode: OutputMode::Minimal,
        serial_enabled: false,
        vga_enabled: false,
    };
    assert!(!policy.serial_enabled);
    assert!(!policy.vga_enabled);
}

#[test]
fn test_observability_policy_all_enabled() {
    let policy = ObservabilityPolicy {
        production: true,
        output_mode: OutputMode::Debug,
        serial_enabled: true,
        vga_enabled: true,
    };
    assert!(policy.serial_enabled);
    assert!(policy.vga_enabled);
}

#[test]
fn test_serial_log() {
    serial_log("Test log message");
}

#[test]
fn test_serial_log_redacted() {
    serial_log_redacted("Test redacted message");
}
