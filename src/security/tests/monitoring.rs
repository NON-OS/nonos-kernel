// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Security monitoring and event tracking tests

extern crate alloc;

use crate::security::monitoring::monitor::{
    get_recent_events, get_stats, is_enabled, log_event, set_enabled, MonitorStats, SecurityEvent,
    SecurityEventType,
};
use crate::test::framework::TestResult;
use alloc::format;
use alloc::string::String;
use alloc::vec;

pub(crate) fn test_security_event_type_suspicious_memory() -> TestResult {
    let event_type = SecurityEventType::SuspiciousMemoryAccess;
    if event_type != SecurityEventType::SuspiciousMemoryAccess {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_unauthorized_network() -> TestResult {
    let event_type = SecurityEventType::UnauthorizedNetworkAccess;
    if event_type != SecurityEventType::UnauthorizedNetworkAccess {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_process_anomaly() -> TestResult {
    let event_type = SecurityEventType::ProcessAnomaly;
    if event_type != SecurityEventType::ProcessAnomaly {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_hardware_tamper() -> TestResult {
    let event_type = SecurityEventType::HardwareTamper;
    if event_type != SecurityEventType::HardwareTamper {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_privilege_escalation() -> TestResult {
    let event_type = SecurityEventType::PrivilegeEscalation;
    if event_type != SecurityEventType::PrivilegeEscalation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_syscall_anomaly() -> TestResult {
    let event_type = SecurityEventType::SyscallAnomaly;
    if event_type != SecurityEventType::SyscallAnomaly {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_filesystem_violation() -> TestResult {
    let event_type = SecurityEventType::FilesystemViolation;
    if event_type != SecurityEventType::FilesystemViolation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_capability_abuse() -> TestResult {
    let event_type = SecurityEventType::CapabilityAbuse;
    if event_type != SecurityEventType::CapabilityAbuse {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_privacy_violation() -> TestResult {
    let event_type = SecurityEventType::PrivacyViolation;
    if event_type != SecurityEventType::PrivacyViolation {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_rootkit_detection() -> TestResult {
    let event_type = SecurityEventType::RootkitDetection;
    if event_type != SecurityEventType::RootkitDetection {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_integrity_breach() -> TestResult {
    let event_type = SecurityEventType::IntegrityBreach;
    if event_type != SecurityEventType::IntegrityBreach {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_equality() -> TestResult {
    if SecurityEventType::SuspiciousMemoryAccess != SecurityEventType::SuspiciousMemoryAccess {
        return TestResult::Fail;
    }
    if SecurityEventType::SuspiciousMemoryAccess == SecurityEventType::RootkitDetection {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_clone() -> TestResult {
    let et1 = SecurityEventType::ProcessAnomaly;
    let et2 = et1.clone();
    if et1 != et2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_copy() -> TestResult {
    let et1 = SecurityEventType::HardwareTamper;
    let et2 = et1;
    if et1 != et2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_fields() -> TestResult {
    let event = SecurityEvent {
        timestamp: 1000,
        event_type: SecurityEventType::SuspiciousMemoryAccess,
        severity: 3,
        description: String::from("Test event"),
        process_id: Some(123),
        module: Some(String::from("test_module")),
        extra_tags: Some(vec![String::from("tag1")]),
    };
    if event.timestamp != 1000 {
        return TestResult::Fail;
    }
    if event.event_type != SecurityEventType::SuspiciousMemoryAccess {
        return TestResult::Fail;
    }
    if event.severity != 3 {
        return TestResult::Fail;
    }
    if event.description != "Test event" {
        return TestResult::Fail;
    }
    if event.process_id != Some(123) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_minimal() -> TestResult {
    let event = SecurityEvent {
        timestamp: 0,
        event_type: SecurityEventType::IntegrityBreach,
        severity: 0,
        description: String::new(),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    if !event.process_id.is_none() {
        return TestResult::Fail;
    }
    if !event.module.is_none() {
        return TestResult::Fail;
    }
    if !event.extra_tags.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_clone() -> TestResult {
    let event = SecurityEvent {
        timestamp: 500,
        event_type: SecurityEventType::PrivilegeEscalation,
        severity: 4,
        description: String::from("Clone test"),
        process_id: Some(456),
        module: None,
        extra_tags: None,
    };
    let cloned = event.clone();
    if event.timestamp != cloned.timestamp {
        return TestResult::Fail;
    }
    if event.event_type != cloned.event_type {
        return TestResult::Fail;
    }
    if event.severity != cloned.severity {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_event() -> TestResult {
    log_event(
        SecurityEventType::SuspiciousMemoryAccess,
        1,
        String::from("Test log event"),
        Some(1),
        Some(String::from("test")),
        None,
    );
    TestResult::Pass
}

pub(crate) fn test_log_event_minimal() -> TestResult {
    log_event(SecurityEventType::IntegrityBreach, 0, String::from("Minimal"), None, None, None);
    TestResult::Pass
}

pub(crate) fn test_log_event_high_severity() -> TestResult {
    log_event(
        SecurityEventType::RootkitDetection,
        4,
        String::from("Critical event"),
        Some(999),
        Some(String::from("security")),
        Some(vec![String::from("rootkit"), String::from("alert")]),
    );
    TestResult::Pass
}

pub(crate) fn test_get_recent_events() -> TestResult {
    let events = get_recent_events(10);
    let _ = events.len();
    TestResult::Pass
}

pub(crate) fn test_get_recent_events_zero() -> TestResult {
    let events = get_recent_events(0);
    if !events.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_stats() -> TestResult {
    let stats = get_stats();
    let _ = stats.total_events.load(core::sync::atomic::Ordering::Relaxed);
    TestResult::Pass
}

pub(crate) fn test_set_enabled_true() -> TestResult {
    set_enabled(true);
    if !is_enabled() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_set_enabled_false() -> TestResult {
    set_enabled(false);
    if is_enabled() {
        return TestResult::Fail;
    }
    set_enabled(true);
    TestResult::Pass
}

pub(crate) fn test_is_enabled() -> TestResult {
    let _ = is_enabled();
    TestResult::Pass
}

pub(crate) fn test_security_event_type_all_variants() -> TestResult {
    let types = [
        SecurityEventType::SuspiciousMemoryAccess,
        SecurityEventType::UnauthorizedNetworkAccess,
        SecurityEventType::ProcessAnomaly,
        SecurityEventType::HardwareTamper,
        SecurityEventType::PrivilegeEscalation,
        SecurityEventType::SyscallAnomaly,
        SecurityEventType::FilesystemViolation,
        SecurityEventType::CapabilityAbuse,
        SecurityEventType::PrivacyViolation,
        SecurityEventType::RootkitDetection,
        SecurityEventType::IntegrityBreach,
    ];
    if types.len() != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_all_unique() -> TestResult {
    let types = [
        SecurityEventType::SuspiciousMemoryAccess,
        SecurityEventType::UnauthorizedNetworkAccess,
        SecurityEventType::ProcessAnomaly,
        SecurityEventType::HardwareTamper,
        SecurityEventType::PrivilegeEscalation,
        SecurityEventType::SyscallAnomaly,
        SecurityEventType::FilesystemViolation,
        SecurityEventType::CapabilityAbuse,
        SecurityEventType::PrivacyViolation,
        SecurityEventType::RootkitDetection,
        SecurityEventType::IntegrityBreach,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            if types[i] == types[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_type_debug() -> TestResult {
    let et = SecurityEventType::RootkitDetection;
    let debug_str = format!("{:?}", et);
    if !debug_str.contains("RootkitDetection") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_debug() -> TestResult {
    let event = SecurityEvent {
        timestamp: 100,
        event_type: SecurityEventType::ProcessAnomaly,
        severity: 2,
        description: String::from("Debug test"),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    let debug_str = format!("{:?}", event);
    if !debug_str.contains("SecurityEvent") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_severity_range() -> TestResult {
    for severity in 0..=4 {
        log_event(
            SecurityEventType::IntegrityBreach,
            severity,
            String::from("Severity test"),
            None,
            None,
            None,
        );
    }
    TestResult::Pass
}

pub(crate) fn test_log_multiple_events() -> TestResult {
    for i in 0..5 {
        log_event(
            SecurityEventType::SuspiciousMemoryAccess,
            1,
            format!("Event {}", i),
            Some(i as u64),
            None,
            None,
        );
    }
    TestResult::Pass
}

pub(crate) fn test_security_event_with_all_tags() -> TestResult {
    let event = SecurityEvent {
        timestamp: 200,
        event_type: SecurityEventType::CapabilityAbuse,
        severity: 3,
        description: String::from("With tags"),
        process_id: Some(100),
        module: Some(String::from("capabilities")),
        extra_tags: Some(vec![
            String::from("abuse"),
            String::from("violation"),
            String::from("critical"),
        ]),
    };
    if event.extra_tags.as_ref().unwrap().len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_enabled_toggle() -> TestResult {
    let original = is_enabled();
    set_enabled(!original);
    if is_enabled() == original {
        return TestResult::Fail;
    }
    set_enabled(original);
    if is_enabled() != original {
        return TestResult::Fail;
    }
    TestResult::Pass
}
