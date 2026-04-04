use crate::npkg::*;

#[test]
fn test_sandbox_config_default() {
    let config = SandboxConfig::default();
    assert!(!config.allow_network);
    assert!(!config.allow_root_write);
    assert!(!config.allowed_paths.is_empty());
    assert!(!config.denied_paths.is_empty());
    assert!(config.max_memory > 0);
    assert!(config.max_files > 0);
    assert!(config.timeout_seconds > 0);
}

#[test]
fn test_sandbox_config_default_allowed_paths() {
    let config = SandboxConfig::default();
    assert!(config.allowed_paths.contains(&alloc::string::String::from("/usr")));
    assert!(config.allowed_paths.contains(&alloc::string::String::from("/opt")));
    assert!(config.allowed_paths.contains(&alloc::string::String::from("/etc")));
    assert!(config.allowed_paths.contains(&alloc::string::String::from("/var")));
}

#[test]
fn test_sandbox_config_default_denied_paths() {
    let config = SandboxConfig::default();
    assert!(config.denied_paths.contains(&alloc::string::String::from("/boot")));
    assert!(config.denied_paths.contains(&alloc::string::String::from("/dev")));
    assert!(config.denied_paths.contains(&alloc::string::String::from("/proc")));
    assert!(config.denied_paths.contains(&alloc::string::String::from("/sys")));
    assert!(config.denied_paths.contains(&alloc::string::String::from("/root")));
}

#[test]
fn test_sandbox_config_permissive() {
    let config = SandboxConfig::permissive();
    assert!(config.allow_network);
    assert!(config.allow_root_write);
    assert!(config.denied_paths.is_empty());
    assert!(config.max_memory >= 1024 * 1024 * 1024);
    assert!(config.max_files >= 100000);
    assert!(config.timeout_seconds >= 3600);
}

#[test]
fn test_sandbox_config_restrictive() {
    let config = SandboxConfig::restrictive();
    assert!(!config.allow_network);
    assert!(!config.allow_root_write);
    assert!(config.max_memory <= 64 * 1024 * 1024);
    assert!(config.max_files <= 1000);
    assert!(config.timeout_seconds <= 60);
}

#[test]
fn test_sandbox_config_is_path_allowed_usr() {
    let config = SandboxConfig::default();
    assert!(config.is_path_allowed("/usr/bin/test"));
    assert!(config.is_path_allowed("/usr/lib/libtest.so"));
}

#[test]
fn test_sandbox_config_is_path_allowed_opt() {
    let config = SandboxConfig::default();
    assert!(config.is_path_allowed("/opt/myapp/bin"));
}

#[test]
fn test_sandbox_config_is_path_allowed_etc() {
    let config = SandboxConfig::default();
    assert!(config.is_path_allowed("/etc/myapp.conf"));
}

#[test]
fn test_sandbox_config_is_path_denied_boot() {
    let config = SandboxConfig::default();
    assert!(!config.is_path_allowed("/boot/kernel"));
}

#[test]
fn test_sandbox_config_is_path_denied_dev() {
    let config = SandboxConfig::default();
    assert!(!config.is_path_allowed("/dev/sda"));
}

#[test]
fn test_sandbox_config_is_path_denied_proc() {
    let config = SandboxConfig::default();
    assert!(!config.is_path_allowed("/proc/1/cmdline"));
}

#[test]
fn test_sandbox_config_is_path_denied_sys() {
    let config = SandboxConfig::default();
    assert!(!config.is_path_allowed("/sys/class/net"));
}

#[test]
fn test_sandbox_config_is_path_denied_root() {
    let config = SandboxConfig::default();
    assert!(!config.is_path_allowed("/root/.bashrc"));
}

#[test]
fn test_sandbox_config_permissive_allows_all() {
    let config = SandboxConfig::permissive();
    assert!(config.is_path_allowed("/usr/bin/test"));
    assert!(config.is_path_allowed("/random/path"));
    assert!(config.is_path_allowed("/anything"));
}

#[test]
fn test_sandbox_config_restrictive_limited_paths() {
    let config = SandboxConfig::restrictive();
    assert!(config.is_path_allowed("/usr/share/data"));
    assert!(config.is_path_allowed("/usr/lib/libtest.so"));
}

#[test]
fn test_sandbox_config_clone() {
    let config = SandboxConfig::default();
    let cloned = config.clone();
    assert_eq!(config.allow_network, cloned.allow_network);
    assert_eq!(config.max_memory, cloned.max_memory);
}

#[test]
fn test_sandbox_config_debug_format() {
    let config = SandboxConfig::default();
    let debug_str = alloc::format!("{:?}", config);
    assert!(debug_str.contains("SandboxConfig"));
}

#[test]
fn test_sandboxed_install_structure() {
    let config = SandboxConfig::default();
    let install = SandboxedInstall::new(config);
    assert!(install.get_installed_files().is_empty());
    assert!(install.get_violations().is_empty());
}

#[test]
fn test_sandboxed_install_check_path_allowed() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_path("/usr/bin/test");
    assert!(result.is_ok());
}

#[test]
fn test_sandboxed_install_check_path_denied() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_path("/boot/kernel");
    assert!(result.is_err());
}

#[test]
fn test_sandboxed_install_records_violation() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let _ = install.check_path("/root/secret");
    assert!(!install.get_violations().is_empty());
}

#[test]
fn test_sandboxed_install_check_memory_within_limit() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_memory(1024);
    assert!(result.is_ok());
}

#[test]
fn test_sandboxed_install_check_memory_exceeds_limit() {
    let mut config = SandboxConfig::default();
    config.max_memory = 100;
    let mut install = SandboxedInstall::new(config);
    let result = install.check_memory(1000);
    assert!(result.is_err());
}

#[test]
fn test_sandboxed_install_check_file_count_within_limit() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    let result = install.check_file_count();
    assert!(result.is_ok());
}

#[test]
fn test_sandboxed_install_check_file_count_exceeds_limit() {
    let mut config = SandboxConfig::default();
    config.max_files = 0;
    let mut install = SandboxedInstall::new(config);
    let result = install.check_file_count();
    assert!(result.is_err());
}

#[test]
fn test_sandboxed_install_record_file() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    install.record_file(alloc::string::String::from("/usr/bin/test"));
    assert_eq!(install.get_installed_files().len(), 1);
    assert_eq!(install.get_installed_files()[0], "/usr/bin/test");
}

#[test]
fn test_sandboxed_install_multiple_files() {
    let config = SandboxConfig::default();
    let mut install = SandboxedInstall::new(config);
    install.record_file(alloc::string::String::from("/usr/bin/app"));
    install.record_file(alloc::string::String::from("/usr/lib/libapp.so"));
    install.record_file(alloc::string::String::from("/etc/app.conf"));
    assert_eq!(install.get_installed_files().len(), 3);
}

#[test]
fn test_verify_sandbox_integrity_empty() {
    let files: alloc::vec::Vec<alloc::string::String> = alloc::vec![];
    let result = verify_sandbox_integrity(&files);
    assert!(result.is_ok());
    let issues = result.unwrap();
    assert!(issues.is_empty());
}

#[test]
fn test_sandbox_config_max_memory_values() {
    let default = SandboxConfig::default();
    let permissive = SandboxConfig::permissive();
    let restrictive = SandboxConfig::restrictive();

    assert!(permissive.max_memory > default.max_memory);
    assert!(default.max_memory > restrictive.max_memory);
}

#[test]
fn test_sandbox_config_max_files_values() {
    let default = SandboxConfig::default();
    let permissive = SandboxConfig::permissive();
    let restrictive = SandboxConfig::restrictive();

    assert!(permissive.max_files > default.max_files);
    assert!(default.max_files > restrictive.max_files);
}

#[test]
fn test_sandbox_config_timeout_values() {
    let default = SandboxConfig::default();
    let permissive = SandboxConfig::permissive();
    let restrictive = SandboxConfig::restrictive();

    assert!(permissive.timeout_seconds > default.timeout_seconds);
    assert!(default.timeout_seconds > restrictive.timeout_seconds);
}

#[test]
fn test_sandboxed_install_check_timeout() {
    let config = SandboxConfig::default();
    let install = SandboxedInstall::new(config);
    let result = install.check_timeout();
    assert!(result.is_ok());
}
