use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_pre_install_hook_structure() -> TestResult {
    let hook = PreInstallHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("mkdir -p /opt/test"),
    };
    if hook.package != "test-pkg" {
        return TestResult::Fail;
    }
    if hook.version != "1.0.0" {
        return TestResult::Fail;
    }
    if hook.script.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_post_install_hook_structure() -> TestResult {
    let hook = PostInstallHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("ldconfig"),
        files_installed: alloc::vec![
            alloc::string::String::from("/usr/lib/libtest.so"),
            alloc::string::String::from("/usr/bin/test"),
        ],
    };
    if hook.package != "test-pkg" {
        return TestResult::Fail;
    }
    if hook.files_installed.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pre_remove_hook_structure() -> TestResult {
    let hook = PreRemoveHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("echo 'removing'"),
        files: alloc::vec![alloc::string::String::from("/usr/bin/test")],
    };
    if hook.package != "test-pkg" {
        return TestResult::Fail;
    }
    if hook.files.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_post_remove_hook_structure() -> TestResult {
    let hook = PostRemoveHook {
        package: alloc::string::String::from("test-pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("ldconfig"),
    };
    if hook.package != "test-pkg" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hook_clone() -> TestResult {
    let hook = PreInstallHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("touch /tmp/test"),
    };
    let cloned = hook.clone();
    if hook.package != cloned.package {
        return TestResult::Fail;
    }
    if hook.script != cloned.script {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_post_install_hook_clone() -> TestResult {
    let hook = PostInstallHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("2.0.0"),
        script: alloc::string::String::new(),
        files_installed: alloc::vec![],
    };
    let cloned = hook.clone();
    if hook.version != cloned.version {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pre_remove_hook_clone() -> TestResult {
    let hook = PreRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("3.0.0"),
        script: alloc::string::String::from("echo bye"),
        files: alloc::vec![],
    };
    let cloned = hook.clone();
    if hook.script != cloned.script {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_post_remove_hook_clone() -> TestResult {
    let hook = PostRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("4.0.0"),
        script: alloc::string::String::from("cleanup"),
    };
    let cloned = hook.clone();
    if hook.package != cloned.package {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_run_pre_install_empty_script() -> TestResult {
    let result = run_pre_install("test-pkg", "");
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_run_post_install_empty_script() -> TestResult {
    let result = run_post_install("test-pkg", "");
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_run_pre_remove_empty_script() -> TestResult {
    let result = run_pre_remove("test-pkg", "");
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_run_post_remove_empty_script() -> TestResult {
    let result = run_post_remove("test-pkg", "");
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hook_with_comment() -> TestResult {
    let script = "# This is a comment\n";
    let result = run_pre_install("test", script);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hook_with_empty_lines() -> TestResult {
    let script = "\n\n\n";
    let result = run_post_install("test", script);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hook_script_echo() -> TestResult {
    let script = "echo hello world";
    let result = run_pre_install("test", script);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_hook_debug_format() -> TestResult {
    let hook = PreInstallHook {
        package: alloc::string::String::from("debug-test"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::from("test"),
    };
    let debug_str = alloc::format!("{:?}", hook);
    if !debug_str.contains("PreInstallHook") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_post_install_hook_debug_format() -> TestResult {
    let hook = PostInstallHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::new(),
        files_installed: alloc::vec![],
    };
    let debug_str = alloc::format!("{:?}", hook);
    if !debug_str.contains("PostInstallHook") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pre_remove_hook_debug_format() -> TestResult {
    let hook = PreRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::new(),
        files: alloc::vec![],
    };
    let debug_str = alloc::format!("{:?}", hook);
    if !debug_str.contains("PreRemoveHook") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_post_remove_hook_debug_format() -> TestResult {
    let hook = PostRemoveHook {
        package: alloc::string::String::from("pkg"),
        version: alloc::string::String::from("1.0.0"),
        script: alloc::string::String::new(),
    };
    let debug_str = alloc::format!("{:?}", hook);
    if !debug_str.contains("PostRemoveHook") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
