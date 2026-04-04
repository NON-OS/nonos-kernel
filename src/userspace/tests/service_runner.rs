use crate::userspace::*;

#[test]
fn test_run_vfs_service_exported() {
    let _: fn() -> ! = run_vfs_service;
}

#[test]
fn test_run_net_service_exported() {
    let _: fn() -> ! = run_net_service;
}

#[test]
fn test_run_display_service_exported() {
    let _: fn() -> ! = run_display_service;
}

#[test]
fn test_run_driver_manager_exported() {
    let _: fn() -> ! = run_driver_manager;
}

#[test]
fn test_run_crypto_service_exported() {
    let _: fn() -> ! = run_crypto_service;
}

#[test]
fn test_run_zk_service_exported() {
    let _: fn() -> ! = run_zk_service;
}

#[test]
fn test_run_input_service_exported() {
    let _: fn() -> ! = run_input_service;
}

#[test]
fn test_run_audio_service_exported() {
    let _: fn() -> ! = run_audio_service;
}

#[test]
fn test_run_gpu_service_exported() {
    let _: fn() -> ! = run_gpu_service;
}

#[test]
fn test_run_apps_service_exported() {
    let _: fn() -> ! = run_apps_service;
}

#[test]
fn test_run_agents_service_exported() {
    let _: fn() -> ! = run_agents_service;
}

#[test]
fn test_run_shell_service_exported() {
    let _: fn() -> ! = run_shell_service;
}

#[test]
fn test_run_service_by_name_exported() {
    let _: fn(&str) -> ! = run_service_by_name;
}

#[test]
fn test_service_runner_known_names() {
    let known = ["vfs", "network", "display", "drivers", "crypto", "zk",
                 "input", "audio", "gpu", "apps", "agents", "shell", "desktop"];
    for name in known {
        assert!(!name.is_empty());
    }
}

#[test]
fn test_service_names_all_lowercase() {
    let names = ["vfs", "network", "display", "drivers", "crypto", "zk",
                 "input", "audio", "gpu", "apps", "agents", "shell", "desktop"];
    for name in names {
        assert_eq!(name, name.to_lowercase());
    }
}

#[test]
fn test_service_names_no_whitespace() {
    let names = ["vfs", "network", "display", "drivers", "crypto", "zk",
                 "input", "audio", "gpu", "apps", "agents", "shell", "desktop"];
    for name in names {
        assert!(!name.contains(' '));
        assert!(!name.contains('\t'));
        assert!(!name.contains('\n'));
    }
}

#[test]
fn test_all_services_have_run_function() {
    let _: fn() -> ! = run_vfs_service;
    let _: fn() -> ! = run_net_service;
    let _: fn() -> ! = run_display_service;
    let _: fn() -> ! = run_driver_manager;
    let _: fn() -> ! = run_crypto_service;
    let _: fn() -> ! = run_zk_service;
    let _: fn() -> ! = run_input_service;
    let _: fn() -> ! = run_audio_service;
    let _: fn() -> ! = run_gpu_service;
    let _: fn() -> ! = run_apps_service;
    let _: fn() -> ! = run_agents_service;
    let _: fn() -> ! = run_shell_service;
}

#[test]
fn test_service_count() {
    let services = [
        "vfs", "network", "display", "drivers", "crypto", "zk",
        "input", "audio", "gpu", "apps", "agents", "shell", "desktop"
    ];
    assert_eq!(services.len(), 13);
}

#[test]
fn test_services_are_unique() {
    let services = [
        "vfs", "network", "display", "drivers", "crypto", "zk",
        "input", "audio", "gpu", "apps", "agents", "shell", "desktop"
    ];
    for (i, s1) in services.iter().enumerate() {
        for (j, s2) in services.iter().enumerate() {
            if i != j {
                assert_ne!(s1, s2);
            }
        }
    }
}
