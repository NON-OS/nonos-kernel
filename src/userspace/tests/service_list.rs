use crate::test::framework::TestResult;
use crate::userspace::init::{CORE_SERVICES, DRIVER_SERVICES};

pub(crate) fn test_core_services_is_static_slice() -> TestResult {
    let services: &'static [&'static str] = CORE_SERVICES;
    if !(services.len() > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_is_static_slice() -> TestResult {
    let services: &'static [&'static str] = DRIVER_SERVICES;
    if !(services.len() > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_first_is_vfs() -> TestResult {
    if CORE_SERVICES[0] != "vfs" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_second_is_display() -> TestResult {
    if CORE_SERVICES[1] != "display" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_third_is_input() -> TestResult {
    if CORE_SERVICES[2] != "input" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_fourth_is_network() -> TestResult {
    if CORE_SERVICES[3] != "network" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_fifth_is_crypto() -> TestResult {
    if CORE_SERVICES[4] != "crypto" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_sixth_is_zk() -> TestResult {
    if CORE_SERVICES[5] != "zk" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_seventh_is_audio() -> TestResult {
    if CORE_SERVICES[6] != "audio" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_eighth_is_gpu() -> TestResult {
    if CORE_SERVICES[7] != "gpu" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_ninth_is_apps() -> TestResult {
    if CORE_SERVICES[8] != "apps" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_tenth_is_agents() -> TestResult {
    if CORE_SERVICES[9] != "agents" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_eleventh_is_shell() -> TestResult {
    if CORE_SERVICES[10] != "shell" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_twelfth_is_desktop() -> TestResult {
    if CORE_SERVICES[11] != "desktop" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_first_is_drivers() -> TestResult {
    if DRIVER_SERVICES[0] != "drivers" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_all_non_empty_strings() -> TestResult {
    for service in CORE_SERVICES {
        if service.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_all_non_empty_strings() -> TestResult {
    for service in DRIVER_SERVICES {
        if service.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_no_duplicates() -> TestResult {
    for (i, s1) in CORE_SERVICES.iter().enumerate() {
        for (j, s2) in CORE_SERVICES.iter().enumerate() {
            if i != j {
                if s1 == s2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_driver_services_no_duplicates() -> TestResult {
    for (i, s1) in DRIVER_SERVICES.iter().enumerate() {
        for (j, s2) in DRIVER_SERVICES.iter().enumerate() {
            if i != j {
                if s1 == s2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_core_services_no_overlap_with_driver_services() -> TestResult {
    for core in CORE_SERVICES {
        if DRIVER_SERVICES.contains(core) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_services_are_lowercase() -> TestResult {
    for service in CORE_SERVICES {
        if *service != service.to_lowercase() {
            return TestResult::Fail;
        }
    }
    for service in DRIVER_SERVICES {
        if *service != service.to_lowercase() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
