// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::services::registry::{
    list_endpoints, lookup_service, register_endpoint, register_endpoint_simple,
    unregister_endpoint, RegError, ServiceEndpoint, MAX_SERVICES,
};
use crate::test::framework::TestResult;
use alloc::string::String;

pub(crate) fn test_max_services_constant() -> TestResult {
    if MAX_SERVICES != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_services_positive() -> TestResult {
    if MAX_SERVICES == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_services_reasonable_upper_bound() -> TestResult {
    if MAX_SERVICES > 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_fields() -> TestResult {
    let ep = ServiceEndpoint {
        name: String::from("test_svc"),
        port: 1234,
        pid: 42,
        caps_required: 0x1234,
    };
    if ep.name != "test_svc" {
        return TestResult::Fail;
    }
    if ep.port != 1234 {
        return TestResult::Fail;
    }
    if ep.pid != 42 {
        return TestResult::Fail;
    }
    if ep.caps_required != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_empty_name() -> TestResult {
    let ep = ServiceEndpoint { name: String::new(), port: 0, pid: 0, caps_required: 0 };
    if !ep.name.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_clone() -> TestResult {
    let ep1 = ServiceEndpoint {
        name: String::from("clone_test"),
        port: 8080,
        pid: 100,
        caps_required: 0xFF,
    };
    let ep2 = ep1.clone();
    if ep1.name != ep2.name {
        return TestResult::Fail;
    }
    if ep1.port != ep2.port {
        return TestResult::Fail;
    }
    if ep1.pid != ep2.pid {
        return TestResult::Fail;
    }
    if ep1.caps_required != ep2.caps_required {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_debug() -> TestResult {
    let ep =
        ServiceEndpoint { name: String::from("debug_svc"), port: 5000, pid: 1, caps_required: 0 };
    let debug_str = alloc::format!("{:?}", ep);
    if !debug_str.contains("ServiceEndpoint") {
        return TestResult::Fail;
    }
    if !debug_str.contains("debug_svc") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_max_port() -> TestResult {
    let ep = ServiceEndpoint {
        name: String::from("max_port"),
        port: u32::MAX,
        pid: 1,
        caps_required: 0,
    };
    if ep.port != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_max_pid() -> TestResult {
    let ep = ServiceEndpoint {
        name: String::from("max_pid"),
        port: 1000,
        pid: u32::MAX,
        caps_required: 0,
    };
    if ep.pid != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_max_caps() -> TestResult {
    let ep = ServiceEndpoint {
        name: String::from("max_caps"),
        port: 1000,
        pid: 1,
        caps_required: u64::MAX,
    };
    if ep.caps_required != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_full() -> TestResult {
    let err = RegError::Full;
    if err != RegError::Full {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_exists() -> TestResult {
    let err = RegError::Exists;
    if err != RegError::Exists {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_not_found() -> TestResult {
    let err = RegError::NotFound;
    if err != RegError::NotFound {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_permission_denied() -> TestResult {
    let err = RegError::PermissionDenied;
    if err != RegError::PermissionDenied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_equality() -> TestResult {
    if RegError::Full != RegError::Full {
        return TestResult::Fail;
    }
    if RegError::Full == RegError::Exists {
        return TestResult::Fail;
    }
    if RegError::NotFound == RegError::PermissionDenied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_clone() -> TestResult {
    let err1 = RegError::Exists;
    let err2 = err1.clone();
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_copy() -> TestResult {
    let err1 = RegError::NotFound;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_debug() -> TestResult {
    let err = RegError::Full;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("Full") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_all_variants() -> TestResult {
    let errors = [RegError::Full, RegError::Exists, RegError::NotFound, RegError::PermissionDenied];
    if errors.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_all_unique() -> TestResult {
    let errors = [RegError::Full, RegError::Exists, RegError::NotFound, RegError::PermissionDenied];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            if errors[i] == errors[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_list_endpoints_returns_vec() -> TestResult {
    let _eps = list_endpoints();
    TestResult::Pass
}

pub(crate) fn test_lookup_nonexistent_service() -> TestResult {
    let result = lookup_service("definitely_nonexistent_service_xyz");
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_endpoint_returns_result() -> TestResult {
    let result = register_endpoint("test_reg_1", 9000, 1, 0);
    let _ = result;
    TestResult::Pass
}

pub(crate) fn test_register_endpoint_simple_does_not_panic() -> TestResult {
    register_endpoint_simple("simple_test_svc", 9001, 1);
    TestResult::Pass
}

pub(crate) fn test_unregister_nonexistent() -> TestResult {
    let result = unregister_endpoint("nonexistent_unregister_test");
    if result != Err(RegError::NotFound) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_long_name() -> TestResult {
    let long_name = String::from("this_is_a_very_long_service_name_for_testing");
    let ep = ServiceEndpoint { name: long_name.clone(), port: 1000, pid: 1, caps_required: 0 };
    if ep.name != long_name {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_with_unicode_name() -> TestResult {
    let ep = ServiceEndpoint { name: String::from("服务"), port: 1000, pid: 1, caps_required: 0 };
    if ep.name != "服务" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_name_with_numbers() -> TestResult {
    let ep =
        ServiceEndpoint { name: String::from("service123"), port: 1000, pid: 1, caps_required: 0 };
    if ep.name != "service123" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_name_with_underscores() -> TestResult {
    let ep = ServiceEndpoint {
        name: String::from("my_service_v2"),
        port: 1000,
        pid: 1,
        caps_required: 0,
    };
    if ep.name != "my_service_v2" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_port_zero() -> TestResult {
    let ep = ServiceEndpoint { name: String::from("port_zero"), port: 0, pid: 1, caps_required: 0 };
    if ep.port != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_pid_zero() -> TestResult {
    let ep =
        ServiceEndpoint { name: String::from("pid_zero"), port: 1000, pid: 0, caps_required: 0 };
    if ep.pid != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_multiple_caps() -> TestResult {
    let caps = 0x1 | 0x2 | 0x4 | 0x8;
    let ep = ServiceEndpoint {
        name: String::from("multi_caps"),
        port: 1000,
        pid: 1,
        caps_required: caps,
    };
    if ep.caps_required != 0xF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_debug_exists() -> TestResult {
    let err = RegError::Exists;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("Exists") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_debug_not_found() -> TestResult {
    let err = RegError::NotFound;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("NotFound") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_reg_error_debug_permission_denied() -> TestResult {
    let err = RegError::PermissionDenied;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("PermissionDenied") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_default_like() -> TestResult {
    let ep = ServiceEndpoint { name: String::new(), port: 0, pid: 0, caps_required: 0 };
    if !ep.name.is_empty() {
        return TestResult::Fail;
    }
    if ep.port != 0 {
        return TestResult::Fail;
    }
    if ep.pid != 0 {
        return TestResult::Fail;
    }
    if ep.caps_required != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_list_endpoints_type() -> TestResult {
    let eps: alloc::vec::Vec<ServiceEndpoint> = list_endpoints();
    let _ = eps.len();
    TestResult::Pass
}

pub(crate) fn test_lookup_service_type() -> TestResult {
    let result: Option<ServiceEndpoint> = lookup_service("type_test");
    if result.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_endpoint_type() -> TestResult {
    let result: Result<(), RegError> = register_endpoint("type_test_reg", 9002, 1, 0);
    let _ = result;
    TestResult::Pass
}

pub(crate) fn test_unregister_endpoint_type() -> TestResult {
    let result: Result<(), RegError> = unregister_endpoint("type_test_unreg");
    let _ = result;
    TestResult::Pass
}
