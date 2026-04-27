// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Security audit logging tests

extern crate alloc;

use crate::security::*;
use crate::test::framework::TestResult;
use alloc::format;
use alloc::string::String;
use alloc::vec;

pub(crate) fn test_audit_severity_info() -> TestResult {
    let severity = AuditSeverity::Info;
    if severity != AuditSeverity::Info {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_warning() -> TestResult {
    let severity = AuditSeverity::Warning;
    if severity != AuditSeverity::Warning {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_error() -> TestResult {
    let severity = AuditSeverity::Error;
    if severity != AuditSeverity::Error {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_critical() -> TestResult {
    let severity = AuditSeverity::Critical;
    if severity != AuditSeverity::Critical {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_emergency() -> TestResult {
    let severity = AuditSeverity::Emergency;
    if severity != AuditSeverity::Emergency {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_equality() -> TestResult {
    if AuditSeverity::Info != AuditSeverity::Info {
        return TestResult::Fail;
    }
    if AuditSeverity::Info == AuditSeverity::Warning {
        return TestResult::Fail;
    }
    if AuditSeverity::Critical == AuditSeverity::Emergency {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_copy() -> TestResult {
    let s1 = AuditSeverity::Critical;
    let s2 = s1;
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_audit_event_fields() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: 1000,
        subsystem: "test",
        severity: AuditSeverity::Info,
        description: String::from("Test event"),
        process_id: Some(123),
        module: Some(String::from("test_module")),
        extra_tags: Some(vec![String::from("tag1"), String::from("tag2")]),
    };
    if event.timestamp != 1000 {
        return TestResult::Fail;
    }
    if event.subsystem != "test" {
        return TestResult::Fail;
    }
    if event.severity != AuditSeverity::Info {
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

pub(crate) fn test_security_audit_event_minimal() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: 0,
        subsystem: "security",
        severity: AuditSeverity::Warning,
        description: String::from("Minimal event"),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    if event.process_id.is_some() {
        return TestResult::Fail;
    }
    if event.module.is_some() {
        return TestResult::Fail;
    }
    if event.extra_tags.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_audit_event_clone() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: 500,
        subsystem: "kernel",
        severity: AuditSeverity::Error,
        description: String::from("Clone test"),
        process_id: Some(456),
        module: None,
        extra_tags: None,
    };
    let cloned = event.clone();
    if event.timestamp != cloned.timestamp {
        return TestResult::Fail;
    }
    if event.description != cloned.description {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_security_event() -> TestResult {
    log_security_event(
        "test_subsystem",
        AuditSeverity::Info,
        String::from("Test security event"),
        Some(1),
        Some(String::from("module")),
        None,
    );
    TestResult::Pass
}

pub(crate) fn test_log_security_event_minimal() -> TestResult {
    log_security_event(
        "security",
        AuditSeverity::Warning,
        String::from("Minimal log"),
        None,
        None,
        None,
    );
    TestResult::Pass
}

pub(crate) fn test_log_security_violation() -> TestResult {
    log_security_violation(String::from("Test violation"), AuditSeverity::Critical);
    TestResult::Pass
}

pub(crate) fn test_get_audit_log() -> TestResult {
    let log = get_audit_log();
    let _ = log.len();
    TestResult::Pass
}

pub(crate) fn test_clear_audit_log() -> TestResult {
    log_security_event("test", AuditSeverity::Info, String::from("Before clear"), None, None, None);
    clear_audit_log();
    let log = get_audit_log();
    if !log.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_event_alias() -> TestResult {
    let event: AuditEvent = SecurityAuditEvent {
        timestamp: 100,
        subsystem: "alias_test",
        severity: AuditSeverity::Info,
        description: String::from("Alias test"),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    if event.subsystem != "alias_test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_event_function() -> TestResult {
    audit_event(
        "function_test",
        AuditSeverity::Warning,
        String::from("Audit event function"),
        Some(789),
        None,
        None,
    );
    TestResult::Pass
}

pub(crate) fn test_audit_log_multiple_events() -> TestResult {
    clear_audit_log();
    for i in 0..5 {
        log_security_event(
            "batch",
            AuditSeverity::Info,
            format!("Event {}", i),
            Some(i as u64),
            None,
            None,
        );
    }
    let log = get_audit_log();
    if log.len() < 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_all_variants() -> TestResult {
    let severities = [
        AuditSeverity::Info,
        AuditSeverity::Warning,
        AuditSeverity::Error,
        AuditSeverity::Critical,
        AuditSeverity::Emergency,
    ];
    if severities.len() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_audit_event_with_tags() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: 200,
        subsystem: "tags_test",
        severity: AuditSeverity::Info,
        description: String::from("With tags"),
        process_id: None,
        module: None,
        extra_tags: Some(vec![
            String::from("security"),
            String::from("authentication"),
            String::from("failed"),
        ]),
    };
    if event.extra_tags.is_none() {
        return TestResult::Fail;
    }
    if event.extra_tags.as_ref().unwrap().len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_event_debug_format() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: 300,
        subsystem: "debug",
        severity: AuditSeverity::Error,
        description: String::from("Debug test"),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    let debug_str = format!("{:?}", event);
    if !debug_str.contains("debug") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_audit_severity_debug_format() -> TestResult {
    let severity = AuditSeverity::Emergency;
    let debug_str = format!("{:?}", severity);
    if !debug_str.contains("Emergency") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_log_security_event_all_fields() -> TestResult {
    log_security_event(
        "full_test",
        AuditSeverity::Critical,
        String::from("Full event"),
        Some(999),
        Some(String::from("critical_module")),
        Some(vec![String::from("urgent"), String::from("action_required")]),
    );
    TestResult::Pass
}

pub(crate) fn test_security_audit_event_timestamp_range() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: u64::MAX,
        subsystem: "range",
        severity: AuditSeverity::Info,
        description: String::from("Max timestamp"),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    if event.timestamp != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_audit_event_empty_description() -> TestResult {
    let event = SecurityAuditEvent {
        timestamp: 0,
        subsystem: "empty",
        severity: AuditSeverity::Info,
        description: String::new(),
        process_id: None,
        module: None,
        extra_tags: None,
    };
    if !event.description.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
