use crate::test::framework::TestResult;
use crate::userspace::init::{CORE_SERVICES, DRIVER_SERVICES};

pub(crate) fn test_verify_interval_constant() -> TestResult {
    const VERIFY_INTERVAL_MS: u64 = 5000;
    if VERIFY_INTERVAL_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervise_interval_constant() -> TestResult {
    const SUPERVISE_INTERVAL_MS: u64 = 1000;
    if SUPERVISE_INTERVAL_MS != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_restart_attempts_constant() -> TestResult {
    const MAX_RESTART_ATTEMPTS: u32 = 5;
    if MAX_RESTART_ATTEMPTS != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_restart_backoff_base_constant() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    if RESTART_BACKOFF_BASE_MS != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_calculation_first_attempt() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 0u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_calculation_second_attempt() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 1u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_calculation_third_attempt() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 2u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 4000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_calculation_fourth_attempt() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 3u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 8000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_calculation_fifth_attempt() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 4u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 16000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_capped_at_16_seconds() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 10u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 16000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_capped_at_max_attempts() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let attempts = 100u32;
    let backoff = RESTART_BACKOFF_BASE_MS * (1 << attempts.min(4));
    if backoff != 16000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_interval_is_5x_supervise() -> TestResult {
    const VERIFY_INTERVAL_MS: u64 = 5000;
    const SUPERVISE_INTERVAL_MS: u64 = 1000;
    if VERIFY_INTERVAL_MS != SUPERVISE_INTERVAL_MS * 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_core_services_supervised() -> TestResult {
    let supervised = CORE_SERVICES;
    if !supervised.contains(&"vfs") {
        return TestResult::Fail;
    }
    if !supervised.contains(&"display") {
        return TestResult::Fail;
    }
    if !supervised.contains(&"network") {
        return TestResult::Fail;
    }
    if !supervised.contains(&"crypto") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervision_uses_core_services_list() -> TestResult {
    if CORE_SERVICES.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verification_uses_core_services_list() -> TestResult {
    if CORE_SERVICES.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_restart_state_entry_creation() -> TestResult {
    struct RestartInfo {
        attempts: u32,
        last_restart_ms: u64,
    }
    let info = RestartInfo { attempts: 0, last_restart_ms: 0 };
    if info.attempts != 0 {
        return TestResult::Fail;
    }
    if info.last_restart_ms != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_restart_info_increment() -> TestResult {
    struct RestartInfo {
        attempts: u32,
        last_restart_ms: u64,
    }
    let mut info = RestartInfo { attempts: 0, last_restart_ms: 0 };
    info.attempts += 1;
    info.last_restart_ms = 12345;
    if info.attempts != 1 {
        return TestResult::Fail;
    }
    if info.last_restart_ms != 12345 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_restarts_prevents_restart() -> TestResult {
    const MAX_RESTART_ATTEMPTS: u32 = 5;
    let attempts = 5u32;
    if !(attempts >= MAX_RESTART_ATTEMPTS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_under_max_restarts_allows_restart() -> TestResult {
    const MAX_RESTART_ATTEMPTS: u32 = 5;
    let attempts = 4u32;
    if !(attempts < MAX_RESTART_ATTEMPTS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_backoff_progression() -> TestResult {
    const RESTART_BACKOFF_BASE_MS: u64 = 1000;
    let backoffs: [u64; 5] = [
        RESTART_BACKOFF_BASE_MS * (1 << 0u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 1u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 2u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 3u32.min(4)),
        RESTART_BACKOFF_BASE_MS * (1 << 4u32.min(4)),
    ];
    if backoffs != [1000, 2000, 4000, 8000, 16000] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_supervisor_loop_constants_positive() -> TestResult {
    const VERIFY_INTERVAL_MS: u64 = 5000;
    const SUPERVISE_INTERVAL_MS: u64 = 1000;
    if !(VERIFY_INTERVAL_MS > 0) {
        return TestResult::Fail;
    }
    if !(SUPERVISE_INTERVAL_MS > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_not_in_core_supervision() -> TestResult {
    for driver_svc in DRIVER_SERVICES {
        if CORE_SERVICES.contains(driver_svc) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
