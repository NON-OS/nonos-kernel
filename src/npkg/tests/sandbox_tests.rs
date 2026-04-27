use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_sandbox_config_default() -> TestResult {
    let config = SandboxConfig::default();
    if config.allow_network {
        return TestResult::Fail;
    }
    if config.allow_root_write {
        return TestResult::Fail;
    }
    if config.allowed_paths.is_empty() {
        return TestResult::Fail;
    }
    if config.denied_paths.is_empty() {
        return TestResult::Fail;
    }
    if config.max_memory <= 0 {
        return TestResult::Fail;
    }
    if config.max_files <= 0 {
        return TestResult::Fail;
    }
    if config.timeout_seconds <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_default_allowed_paths() -> TestResult {
    let config = SandboxConfig::default();
    if !config.allowed_paths.contains(&alloc::string::String::from("/usr")) {
        return TestResult::Fail;
    }
    if !config.allowed_paths.contains(&alloc::string::String::from("/opt")) {
        return TestResult::Fail;
    }
    if !config.allowed_paths.contains(&alloc::string::String::from("/etc")) {
        return TestResult::Fail;
    }
    if !config.allowed_paths.contains(&alloc::string::String::from("/var")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_default_denied_paths() -> TestResult {
    let config = SandboxConfig::default();
    if !config.denied_paths.contains(&alloc::string::String::from("/boot")) {
        return TestResult::Fail;
    }
    if !config.denied_paths.contains(&alloc::string::String::from("/dev")) {
        return TestResult::Fail;
    }
    if !config.denied_paths.contains(&alloc::string::String::from("/proc")) {
        return TestResult::Fail;
    }
    if !config.denied_paths.contains(&alloc::string::String::from("/sys")) {
        return TestResult::Fail;
    }
    if !config.denied_paths.contains(&alloc::string::String::from("/root")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_permissive() -> TestResult {
    let config = SandboxConfig::permissive();
    if !config.allow_network {
        return TestResult::Fail;
    }
    if !config.allow_root_write {
        return TestResult::Fail;
    }
    if !config.denied_paths.is_empty() {
        return TestResult::Fail;
    }
    if config.max_memory < 1024 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if config.max_files < 100000 {
        return TestResult::Fail;
    }
    if config.timeout_seconds < 3600 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_restrictive() -> TestResult {
    let config = SandboxConfig::restrictive();
    if config.allow_network {
        return TestResult::Fail;
    }
    if config.allow_root_write {
        return TestResult::Fail;
    }
    if config.max_memory > 64 * 1024 * 1024 {
        return TestResult::Fail;
    }
    if config.max_files > 1000 {
        return TestResult::Fail;
    }
    if config.timeout_seconds > 60 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_allowed_usr() -> TestResult {
    let config = SandboxConfig::default();
    if !config.is_path_allowed("/usr/bin/test") {
        return TestResult::Fail;
    }
    if !config.is_path_allowed("/usr/lib/libtest.so") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_allowed_opt() -> TestResult {
    let config = SandboxConfig::default();
    if !config.is_path_allowed("/opt/myapp/bin") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_allowed_etc() -> TestResult {
    let config = SandboxConfig::default();
    if !config.is_path_allowed("/etc/myapp.conf") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_denied_boot() -> TestResult {
    let config = SandboxConfig::default();
    if config.is_path_allowed("/boot/kernel") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_denied_dev() -> TestResult {
    let config = SandboxConfig::default();
    if config.is_path_allowed("/dev/sda") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_denied_proc() -> TestResult {
    let config = SandboxConfig::default();
    if config.is_path_allowed("/proc/1/cmdline") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_denied_sys() -> TestResult {
    let config = SandboxConfig::default();
    if config.is_path_allowed("/sys/class/net") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_is_path_denied_root() -> TestResult {
    let config = SandboxConfig::default();
    if config.is_path_allowed("/root/.bashrc") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_permissive_allows_all() -> TestResult {
    let config = SandboxConfig::permissive();
    if !config.is_path_allowed("/usr/bin/test") {
        return TestResult::Fail;
    }
    if !config.is_path_allowed("/random/path") {
        return TestResult::Fail;
    }
    if !config.is_path_allowed("/anything") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_restrictive_limited_paths() -> TestResult {
    let config = SandboxConfig::restrictive();
    if !config.is_path_allowed("/usr/share/data") {
        return TestResult::Fail;
    }
    if !config.is_path_allowed("/usr/lib/libtest.so") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_clone() -> TestResult {
    let config = SandboxConfig::default();
    let cloned = config.clone();
    if config.allow_network != cloned.allow_network {
        return TestResult::Fail;
    }
    if config.max_memory != cloned.max_memory {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_debug_format() -> TestResult {
    let config = SandboxConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    if !debug_str.contains("SandboxConfig") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_structure() -> TestResult {
    let config = SandboxConfig::default();
    let install = SandboxedInstall::new(config);
    if !install.get_installed_files().is_empty() {
        return TestResult::Fail;
    }
    if !install.get_violations().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_path_allowed() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_path("/usr/bin/test");
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_path_denied() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_path("/boot/kernel");
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_records_violation() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let _ = install.check_path("/root/secret");
    if install.get_violations().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_memory_within_limit() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_memory(1024);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_memory_exceeds_limit() -> TestResult {
    let mut config = SandboxConfig::default();
    config.max_memory = 100;
    let mut install = SandboxedInstall::new(config);
    let result = install.check_memory(1000);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_file_count_within_limit() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_file_count();
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_file_count_exceeds_limit() -> TestResult {
    let mut config = SandboxConfig::default();
    config.max_files = 0;
    let mut install = SandboxedInstall::new(config);
    let result = install.check_file_count();
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_record_file() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    install.record_file(alloc::string::String::from("/usr/bin/test"));
    if install.get_installed_files().len() != 1 {
        return TestResult::Fail;
    }
    if install.get_installed_files()[0] != "/usr/bin/test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_multiple_files() -> TestResult {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    install.record_file(alloc::string::String::from("/usr/bin/app"));
    install.record_file(alloc::string::String::from("/usr/lib/libapp.so"));
    install.record_file(alloc::string::String::from("/etc/app.conf"));
    if install.get_installed_files().len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_verify_sandbox_integrity_empty() -> TestResult {
    let files: alloc::vec::Vec<alloc::string::String> = alloc::vec![];
    let result = verify_sandbox_integrity(&files);
    if result.is_err() {
        return TestResult::Fail;
    }
    let issues = result.unwrap();
    if !issues.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_max_memory_values() -> TestResult {
    let default = SandboxConfig::default();
    let permissive = SandboxConfig::permissive();
    let restrictive = SandboxConfig::restrictive();

    if permissive.max_memory <= default.max_memory {
        return TestResult::Fail;
    }
    if default.max_memory <= restrictive.max_memory {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_max_files_values() -> TestResult {
    let default = SandboxConfig::default();
    let permissive = SandboxConfig::permissive();
    let restrictive = SandboxConfig::restrictive();

    if permissive.max_files <= default.max_files {
        return TestResult::Fail;
    }
    if default.max_files <= restrictive.max_files {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandbox_config_timeout_values() -> TestResult {
    let default = SandboxConfig::default();
    let permissive = SandboxConfig::permissive();
    let restrictive = SandboxConfig::restrictive();

    if permissive.timeout_seconds <= default.timeout_seconds {
        return TestResult::Fail;
    }
    if default.timeout_seconds <= restrictive.timeout_seconds {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sandboxed_install_check_timeout() -> TestResult {
    let config = SandboxConfig::default();
    let install = SandboxedInstall::new(config);
    let result = install.check_timeout();
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
