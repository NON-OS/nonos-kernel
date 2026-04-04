use crate::npkg::*;

#[test]
fn test_pre_install_hook_structure() {
    let hook = PreInstallHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("mkdir -p /opt/test"),
    };
    assert_eq!(hook.package, "test-pkg");
    assert_eq!(hook.version, "1.0.0");
    assert!(!hook.script.is_empty());
}

#[test]
fn test_post_install_hook_structure() {
    let hook = PostInstallHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("ldconfig"),
        files_installed: alloc::vec![
            alloc::string::String::from("/usr/lib/libtest.so"),
            alloc::string::String::from("/usr/bin/test"),
        ],
    };
    assert_eq!(hook.package, "test-pkg");
    assert_eq!(hook.files_installed.len(), 2);
}

#[test]
fn test_pre_remove_hook_structure() {
    let hook = PreRemoveHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("echo 'removing'"),
        files: alloc::vec![alloc::string::String::from("/usr/bin/test")],
    };
    assert_eq!(hook.package, "test-pkg");
    assert_eq!(hook.files.len(), 1);
}

#[test]
fn test_post_remove_hook_structure() {
    let hook = PostRemoveHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("ldconfig"),
    };
    assert_eq!(hook.package, "test-pkg");
}

#[test]
fn test_hook_clone() {
    let hook = PreInstallHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("touch /tmp/test"),
    };
    let cloned = hook.clone();
    assert_eq!(hook.package, cloned.package);
    assert_eq!(hook.script, cloned.script);
}

#[test]
fn test_post_install_hook_clone() {
    let hook = PostInstallHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("2.0.0"),
        script: alloc::string::String::new(),
        files_installed: alloc::vec![],
    };
    let cloned = hook.clone();
    assert_eq!(hook.version, cloned.version);
}

#[test]
fn test_pre_remove_hook_clone() {
    let hook = PreRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("3.0.0"),
        script: alloc::string::String::from("echo bye"),
        files: alloc::vec![],
    };
    let cloned = hook.clone();
    assert_eq!(hook.script, cloned.script);
}

#[test]
fn test_post_remove_hook_clone() {
    let hook = PostRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("4.0.0"),
        script: alloc::string::String::from("cleanup"),
    };
    let cloned = hook.clone();
    assert_eq!(hook.package, cloned.package);
}

#[test]
fn test_run_pre_install_empty_script() {
    let result = run_pre_install("test-pkg", "");
    assert!(result.is_ok());
}

#[test]
fn test_run_post_install_empty_script() {
    let result = run_post_install("test-pkg", "");
    assert!(result.is_ok());
}

#[test]
fn test_run_pre_remove_empty_script() {
    let result = run_pre_remove("test-pkg", "");
    assert!(result.is_ok());
}

#[test]
fn test_run_post_remove_empty_script() {
    let result = run_post_remove("test-pkg", "");
    assert!(result.is_ok());
}

#[test]
fn test_hook_with_comment() {
    let script = "# This is a comment\n";
    let result = run_pre_install("test", script);
    assert!(result.is_ok());
}

#[test]
fn test_hook_with_empty_lines() {
    let script = "\n\n\n";
    let result = run_post_install("test", script);
    assert!(result.is_ok());
}

#[test]
fn test_hook_script_echo() {
    let script = "echo hello world";
    let result = run_pre_install("test", script);
    assert!(result.is_ok());
}

#[test]
fn test_hook_debug_format() {
    let hook = PreInstallHook {
        package: alloc::string::String::from("debug-test"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("test"),
    };
    let debug_str = alloc::format!("{:?}", hook);
    assert!(debug_str.contains("PreInstallHook"));
}

#[test]
fn test_post_install_hook_debug_format() {
    let hook = PostInstallHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::new(),
        files_installed: alloc::vec![],
    };
    let debug_str = alloc::format!("{:?}", hook);
    assert!(debug_str.contains("PostInstallHook"));
}

#[test]
fn test_pre_remove_hook_debug_format() {
    let hook = PreRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::new(),
        files: alloc::vec![],
    };
    let debug_str = alloc::format!("{:?}", hook);
    assert!(debug_str.contains("PreRemoveHook"));
}

#[test]
fn test_post_remove_hook_debug_format() {
    let hook = PostRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::new(),
    };
    let debug_str = alloc::format!("{:?}", hook);
    assert!(debug_str.contains("PostRemoveHook"));
}
