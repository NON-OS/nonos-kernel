use crate::test::framework::TestResult;
use crate::userspace::init::{CORE_SERVICES, DRIVER_SERVICES};
use crate::userspace::*;

pub(crate) fn test_core_services_not_empty() -> TestResult {
    if CORE_SERVICES.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_not_empty() -> TestResult {
    if DRIVER_SERVICES.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_vfs() -> TestResult {
    if !CORE_SERVICES.contains(&"vfs") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_display() -> TestResult {
    if !CORE_SERVICES.contains(&"display") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_input() -> TestResult {
    if !CORE_SERVICES.contains(&"input") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_network() -> TestResult {
    if !CORE_SERVICES.contains(&"network") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_crypto() -> TestResult {
    if !CORE_SERVICES.contains(&"crypto") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_zk() -> TestResult {
    if !CORE_SERVICES.contains(&"zk") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_audio() -> TestResult {
    if !CORE_SERVICES.contains(&"audio") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_gpu() -> TestResult {
    if !CORE_SERVICES.contains(&"gpu") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_apps() -> TestResult {
    if !CORE_SERVICES.contains(&"apps") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_agents() -> TestResult {
    if !CORE_SERVICES.contains(&"agents") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_shell() -> TestResult {
    if !CORE_SERVICES.contains(&"shell") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_contains_desktop() -> TestResult {
    if !CORE_SERVICES.contains(&"desktop") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_contains_drivers() -> TestResult {
    if !DRIVER_SERVICES.contains(&"drivers") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_count() -> TestResult {
    if CORE_SERVICES.len() != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_count() -> TestResult {
    if DRIVER_SERVICES.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_run_init_exported() -> TestResult {
    let _: fn() -> ! = run_init;
    TestResult::Pass
}
