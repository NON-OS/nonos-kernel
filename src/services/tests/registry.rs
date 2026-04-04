// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::services::registry::{
    ServiceEndpoint, RegError, MAX_SERVICES,
    register_endpoint, register_endpoint_simple, lookup_service,
    unregister_endpoint, list_endpoints,
};
use alloc::string::String;

#[test]
fn test_max_services_constant() {
    assert_eq!(MAX_SERVICES, 64);
}

#[test]
fn test_max_services_positive() {
    assert!(MAX_SERVICES > 0);
}

#[test]
fn test_max_services_reasonable_upper_bound() {
    assert!(MAX_SERVICES <= 1024);
}

#[test]
fn test_service_endpoint_fields() {
    let ep = ServiceEndpoint {
        name: String::from("test_svc"),
        port: 1234,
        pid: 42,
        caps_required: 0x1234,
    };
    assert_eq!(ep.name, "test_svc");
    assert_eq!(ep.port, 1234);
    assert_eq!(ep.pid, 42);
    assert_eq!(ep.caps_required, 0x1234);
}

#[test]
fn test_service_endpoint_empty_name() {
    let ep = ServiceEndpoint {
        name: String::new(),
        port: 0,
        pid: 0,
        caps_required: 0,
    };
    assert!(ep.name.is_empty());
}

#[test]
fn test_service_endpoint_clone() {
    let ep1 = ServiceEndpoint {
        name: String::from("clone_test"),
        port: 8080,
        pid: 100,
        caps_required: 0xFF,
    };
    let ep2 = ep1.clone();
    assert_eq!(ep1.name, ep2.name);
    assert_eq!(ep1.port, ep2.port);
    assert_eq!(ep1.pid, ep2.pid);
    assert_eq!(ep1.caps_required, ep2.caps_required);
}

#[test]
fn test_service_endpoint_debug() {
    let ep = ServiceEndpoint {
        name: String::from("debug_svc"),
        port: 5000,
        pid: 1,
        caps_required: 0,
    };
    let debug_str = alloc::format!("{:?}", ep);
    assert!(debug_str.contains("ServiceEndpoint"));
    assert!(debug_str.contains("debug_svc"));
}

#[test]
fn test_service_endpoint_max_port() {
    let ep = ServiceEndpoint {
        name: String::from("max_port"),
        port: u32::MAX,
        pid: 1,
        caps_required: 0,
    };
    assert_eq!(ep.port, u32::MAX);
}

#[test]
fn test_service_endpoint_max_pid() {
    let ep = ServiceEndpoint {
        name: String::from("max_pid"),
        port: 1000,
        pid: u32::MAX,
        caps_required: 0,
    };
    assert_eq!(ep.pid, u32::MAX);
}

#[test]
fn test_service_endpoint_max_caps() {
    let ep = ServiceEndpoint {
        name: String::from("max_caps"),
        port: 1000,
        pid: 1,
        caps_required: u64::MAX,
    };
    assert_eq!(ep.caps_required, u64::MAX);
}

#[test]
fn test_reg_error_full() {
    let err = RegError::Full;
    assert_eq!(err, RegError::Full);
}

#[test]
fn test_reg_error_exists() {
    let err = RegError::Exists;
    assert_eq!(err, RegError::Exists);
}

#[test]
fn test_reg_error_not_found() {
    let err = RegError::NotFound;
    assert_eq!(err, RegError::NotFound);
}

#[test]
fn test_reg_error_permission_denied() {
    let err = RegError::PermissionDenied;
    assert_eq!(err, RegError::PermissionDenied);
}

#[test]
fn test_reg_error_equality() {
    assert_eq!(RegError::Full, RegError::Full);
    assert_ne!(RegError::Full, RegError::Exists);
    assert_ne!(RegError::NotFound, RegError::PermissionDenied);
}

#[test]
fn test_reg_error_clone() {
    let err1 = RegError::Exists;
    let err2 = err1.clone();
    assert_eq!(err1, err2);
}

#[test]
fn test_reg_error_copy() {
    let err1 = RegError::NotFound;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_reg_error_debug() {
    let err = RegError::Full;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("Full"));
}

#[test]
fn test_reg_error_all_variants() {
    let errors = [
        RegError::Full,
        RegError::Exists,
        RegError::NotFound,
        RegError::PermissionDenied,
    ];
    assert_eq!(errors.len(), 4);
}

#[test]
fn test_reg_error_all_unique() {
    let errors = [
        RegError::Full,
        RegError::Exists,
        RegError::NotFound,
        RegError::PermissionDenied,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            assert_ne!(errors[i], errors[j]);
        }
    }
}

#[test]
fn test_list_endpoints_returns_vec() {
    let _eps = list_endpoints();
}

#[test]
fn test_lookup_nonexistent_service() {
    let result = lookup_service("definitely_nonexistent_service_xyz");
    assert!(result.is_none());
}

#[test]
fn test_register_endpoint_returns_result() {
    let result = register_endpoint("test_reg_1", 9000, 1, 0);
    let _ = result;
}

#[test]
fn test_register_endpoint_simple_does_not_panic() {
    register_endpoint_simple("simple_test_svc", 9001, 1);
}

#[test]
fn test_unregister_nonexistent() {
    let result = unregister_endpoint("nonexistent_unregister_test");
    assert_eq!(result, Err(RegError::NotFound));
}

#[test]
fn test_service_endpoint_long_name() {
    let long_name = String::from("this_is_a_very_long_service_name_for_testing");
    let ep = ServiceEndpoint {
        name: long_name.clone(),
        port: 1000,
        pid: 1,
        caps_required: 0,
    };
    assert_eq!(ep.name, long_name);
}

#[test]
fn test_service_endpoint_with_unicode_name() {
    let ep = ServiceEndpoint {
        name: String::from("服务"),
        port: 1000,
        pid: 1,
        caps_required: 0,
    };
    assert_eq!(ep.name, "服务");
}

#[test]
fn test_service_endpoint_name_with_numbers() {
    let ep = ServiceEndpoint {
        name: String::from("service123"),
        port: 1000,
        pid: 1,
        caps_required: 0,
    };
    assert_eq!(ep.name, "service123");
}

#[test]
fn test_service_endpoint_name_with_underscores() {
    let ep = ServiceEndpoint {
        name: String::from("my_service_v2"),
        port: 1000,
        pid: 1,
        caps_required: 0,
    };
    assert_eq!(ep.name, "my_service_v2");
}

#[test]
fn test_service_endpoint_port_zero() {
    let ep = ServiceEndpoint {
        name: String::from("port_zero"),
        port: 0,
        pid: 1,
        caps_required: 0,
    };
    assert_eq!(ep.port, 0);
}

#[test]
fn test_service_endpoint_pid_zero() {
    let ep = ServiceEndpoint {
        name: String::from("pid_zero"),
        port: 1000,
        pid: 0,
        caps_required: 0,
    };
    assert_eq!(ep.pid, 0);
}

#[test]
fn test_service_endpoint_multiple_caps() {
    let caps = 0x1 | 0x2 | 0x4 | 0x8;
    let ep = ServiceEndpoint {
        name: String::from("multi_caps"),
        port: 1000,
        pid: 1,
        caps_required: caps,
    };
    assert_eq!(ep.caps_required, 0xF);
}

#[test]
fn test_reg_error_debug_exists() {
    let err = RegError::Exists;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("Exists"));
}

#[test]
fn test_reg_error_debug_not_found() {
    let err = RegError::NotFound;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("NotFound"));
}

#[test]
fn test_reg_error_debug_permission_denied() {
    let err = RegError::PermissionDenied;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("PermissionDenied"));
}

#[test]
fn test_service_endpoint_default_like() {
    let ep = ServiceEndpoint {
        name: String::new(),
        port: 0,
        pid: 0,
        caps_required: 0,
    };
    assert!(ep.name.is_empty());
    assert_eq!(ep.port, 0);
    assert_eq!(ep.pid, 0);
    assert_eq!(ep.caps_required, 0);
}

#[test]
fn test_list_endpoints_type() {
    let eps: alloc::vec::Vec<ServiceEndpoint> = list_endpoints();
    let _ = eps.len();
}

#[test]
fn test_lookup_service_type() {
    let result: Option<ServiceEndpoint> = lookup_service("type_test");
    assert!(result.is_none());
}

#[test]
fn test_register_endpoint_type() {
    let result: Result<(), RegError> = register_endpoint("type_test_reg", 9002, 1, 0);
    let _ = result;
}

#[test]
fn test_unregister_endpoint_type() {
    let result: Result<(), RegError> = unregister_endpoint("type_test_unreg");
    let _ = result;
}

