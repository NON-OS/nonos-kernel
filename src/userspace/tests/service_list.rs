use crate::userspace::init::{CORE_SERVICES, DRIVER_SERVICES};

#[test]
fn test_core_services_is_static_slice() {
    let services: &'static [&'static str] = CORE_SERVICES;
    assert!(services.len() > 0);
}

#[test]
fn test_driver_services_is_static_slice() {
    let services: &'static [&'static str] = DRIVER_SERVICES;
    assert!(services.len() > 0);
}

#[test]
fn test_core_services_first_is_vfs() {
    assert_eq!(CORE_SERVICES[0], "vfs");
}

#[test]
fn test_core_services_second_is_display() {
    assert_eq!(CORE_SERVICES[1], "display");
}

#[test]
fn test_core_services_third_is_input() {
    assert_eq!(CORE_SERVICES[2], "input");
}

#[test]
fn test_core_services_fourth_is_network() {
    assert_eq!(CORE_SERVICES[3], "network");
}

#[test]
fn test_core_services_fifth_is_crypto() {
    assert_eq!(CORE_SERVICES[4], "crypto");
}

#[test]
fn test_core_services_sixth_is_zk() {
    assert_eq!(CORE_SERVICES[5], "zk");
}

#[test]
fn test_core_services_seventh_is_audio() {
    assert_eq!(CORE_SERVICES[6], "audio");
}

#[test]
fn test_core_services_eighth_is_gpu() {
    assert_eq!(CORE_SERVICES[7], "gpu");
}

#[test]
fn test_core_services_ninth_is_apps() {
    assert_eq!(CORE_SERVICES[8], "apps");
}

#[test]
fn test_core_services_tenth_is_agents() {
    assert_eq!(CORE_SERVICES[9], "agents");
}

#[test]
fn test_core_services_eleventh_is_shell() {
    assert_eq!(CORE_SERVICES[10], "shell");
}

#[test]
fn test_core_services_twelfth_is_desktop() {
    assert_eq!(CORE_SERVICES[11], "desktop");
}

#[test]
fn test_driver_services_first_is_drivers() {
    assert_eq!(DRIVER_SERVICES[0], "drivers");
}

#[test]
fn test_core_services_all_non_empty_strings() {
    for service in CORE_SERVICES {
        assert!(!service.is_empty());
    }
}

#[test]
fn test_driver_services_all_non_empty_strings() {
    for service in DRIVER_SERVICES {
        assert!(!service.is_empty());
    }
}

#[test]
fn test_core_services_no_duplicates() {
    for (i, s1) in CORE_SERVICES.iter().enumerate() {
        for (j, s2) in CORE_SERVICES.iter().enumerate() {
            if i != j {
                assert_ne!(s1, s2);
            }
        }
    }
}

#[test]
fn test_driver_services_no_duplicates() {
    for (i, s1) in DRIVER_SERVICES.iter().enumerate() {
        for (j, s2) in DRIVER_SERVICES.iter().enumerate() {
            if i != j {
                assert_ne!(s1, s2);
            }
        }
    }
}

#[test]
fn test_core_services_no_overlap_with_driver_services() {
    for core in CORE_SERVICES {
        assert!(!DRIVER_SERVICES.contains(core));
    }
}

#[test]
fn test_services_are_lowercase() {
    for service in CORE_SERVICES {
        assert_eq!(*service, service.to_lowercase());
    }
    for service in DRIVER_SERVICES {
        assert_eq!(*service, service.to_lowercase());
    }
}
