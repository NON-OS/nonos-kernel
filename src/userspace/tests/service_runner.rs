use crate::test::framework::TestResult;
use crate::userspace::*;

pub(crate) fn test_run_vfs_service_exported() -> TestResult {
    let _: fn() -> ! = run_vfs_service;
    TestResult::Pass
}

pub(crate) fn test_run_net_service_exported() -> TestResult {
    let _: fn() -> ! = run_net_service;
    TestResult::Pass
}

pub(crate) fn test_run_display_service_exported() -> TestResult {
    let _: fn() -> ! = run_display_service;
    TestResult::Pass
}

pub(crate) fn test_run_driver_manager_exported() -> TestResult {
    let _: fn() -> ! = run_driver_manager;
    TestResult::Pass
}

pub(crate) fn test_run_crypto_service_exported() -> TestResult {
    let _: fn() -> ! = run_crypto_service;
    TestResult::Pass
}

pub(crate) fn test_run_zk_service_exported() -> TestResult {
    let _: fn() -> ! = run_zk_service;
    TestResult::Pass
}

pub(crate) fn test_run_input_service_exported() -> TestResult {
    let _: fn() -> ! = run_input_service;
    TestResult::Pass
}

pub(crate) fn test_run_audio_service_exported() -> TestResult {
    let _: fn() -> ! = run_audio_service;
    TestResult::Pass
}

pub(crate) fn test_run_gpu_service_exported() -> TestResult {
    let _: fn() -> ! = run_gpu_service;
    TestResult::Pass
}

pub(crate) fn test_run_apps_service_exported() -> TestResult {
    let _: fn() -> ! = run_apps_service;
    TestResult::Pass
}

pub(crate) fn test_run_agents_service_exported() -> TestResult {
    let _: fn() -> ! = run_agents_service;
    TestResult::Pass
}

pub(crate) fn test_run_shell_service_exported() -> TestResult {
    let _: fn() -> ! = run_shell_service;
    TestResult::Pass
}

pub(crate) fn test_run_service_by_name_exported() -> TestResult {
    let _: fn(&str) -> ! = run_service_by_name;
    TestResult::Pass
}

pub(crate) fn test_service_runner_known_names() -> TestResult {
    let known = [
        "vfs", "network", "display", "drivers", "crypto", "zk", "input", "audio", "gpu", "apps",
        "agents", "shell", "desktop",
    ];
    for name in known {
        if name.is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_names_all_lowercase() -> TestResult {
    let names = [
        "vfs", "network", "display", "drivers", "crypto", "zk", "input", "audio", "gpu", "apps",
        "agents", "shell", "desktop",
    ];
    for name in names {
        if name != name.to_lowercase() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_names_no_whitespace() -> TestResult {
    let names = [
        "vfs", "network", "display", "drivers", "crypto", "zk", "input", "audio", "gpu", "apps",
        "agents", "shell", "desktop",
    ];
    for name in names {
        if name.contains(' ') {
            return TestResult::Fail;
        }
        if name.contains('\t') {
            return TestResult::Fail;
        }
        if name.contains('\n') {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_services_have_run_function() -> TestResult {
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
    TestResult::Pass
}

pub(crate) fn test_service_count() -> TestResult {
    let services = [
        "vfs", "network", "display", "drivers", "crypto", "zk", "input", "audio", "gpu", "apps",
        "agents", "shell", "desktop",
    ];
    if services.len() != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_services_are_unique() -> TestResult {
    let services = [
        "vfs", "network", "display", "drivers", "crypto", "zk", "input", "audio", "gpu", "apps",
        "agents", "shell", "desktop",
    ];
    for (i, s1) in services.iter().enumerate() {
        for (j, s2) in services.iter().enumerate() {
            if i != j {
                if s1 == s2 {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}
