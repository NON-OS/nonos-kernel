use crate::npkg::installer::{InstallOptions, RemoveOptions, UpgradeOptions};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_install_options_default() -> TestResult {
    let opts = InstallOptions::default();
    if opts.force {
        return TestResult::Fail;
    }
    if opts.no_deps {
        return TestResult::Fail;
    }
    if opts.no_scripts {
        return TestResult::Fail;
    }
    if opts.download_only {
        return TestResult::Fail;
    }
    if opts.as_dependency {
        return TestResult::Fail;
    }
    if opts.reinstall {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_clone() -> TestResult {
    let opts = InstallOptions {
        force: true,
        no_deps: false,
        no_scripts: true,
        download_only: false,
        as_dependency: true,
        reinstall: false,
    };
    let cloned = opts.clone();
    if opts.force != cloned.force {
        return TestResult::Fail;
    }
    if opts.no_scripts != cloned.no_scripts {
        return TestResult::Fail;
    }
    if opts.as_dependency != cloned.as_dependency {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_debug_format() -> TestResult {
    let opts = InstallOptions::default();
    let debug_str = alloc::format!("{:?}", opts);
    if !debug_str.contains("InstallOptions") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_force() -> TestResult {
    let opts = InstallOptions { force: true, ..Default::default() };
    if !opts.force {
        return TestResult::Fail;
    }
    if opts.no_deps {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_no_deps() -> TestResult {
    let opts = InstallOptions { no_deps: true, ..Default::default() };
    if !opts.no_deps {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_no_scripts() -> TestResult {
    let opts = InstallOptions { no_scripts: true, ..Default::default() };
    if !opts.no_scripts {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_download_only() -> TestResult {
    let opts = InstallOptions { download_only: true, ..Default::default() };
    if !opts.download_only {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_as_dependency() -> TestResult {
    let opts = InstallOptions { as_dependency: true, ..Default::default() };
    if !opts.as_dependency {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_reinstall() -> TestResult {
    let opts = InstallOptions { reinstall: true, ..Default::default() };
    if !opts.reinstall {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_default() -> TestResult {
    let opts = RemoveOptions::default();
    if opts.recursive {
        return TestResult::Fail;
    }
    if opts.no_scripts {
        return TestResult::Fail;
    }
    if !opts.keep_config {
        return TestResult::Fail;
    }
    if opts.purge {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_clone() -> TestResult {
    let opts =
        RemoveOptions { recursive: true, no_scripts: false, keep_config: false, purge: true };
    let cloned = opts.clone();
    if opts.recursive != cloned.recursive {
        return TestResult::Fail;
    }
    if opts.purge != cloned.purge {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_debug_format() -> TestResult {
    let opts = RemoveOptions::default();
    let debug_str = alloc::format!("{:?}", opts);
    if !debug_str.contains("RemoveOptions") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_recursive() -> TestResult {
    let opts = RemoveOptions { recursive: true, ..Default::default() };
    if !opts.recursive {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_no_scripts() -> TestResult {
    let opts = RemoveOptions { no_scripts: true, ..Default::default() };
    if !opts.no_scripts {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_keep_config() -> TestResult {
    let opts = RemoveOptions::default();
    if !opts.keep_config {
        return TestResult::Fail;
    }

    let opts_purge = RemoveOptions { keep_config: false, ..Default::default() };
    if opts_purge.keep_config {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_purge() -> TestResult {
    let opts = RemoveOptions { purge: true, ..Default::default() };
    if !opts.purge {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_default() -> TestResult {
    let opts = UpgradeOptions::default();
    if opts.no_deps {
        return TestResult::Fail;
    }
    if opts.no_scripts {
        return TestResult::Fail;
    }
    if opts.download_only {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_clone() -> TestResult {
    let opts = UpgradeOptions { no_deps: true, no_scripts: true, download_only: true };
    let cloned = opts.clone();
    if opts.no_deps != cloned.no_deps {
        return TestResult::Fail;
    }
    if opts.no_scripts != cloned.no_scripts {
        return TestResult::Fail;
    }
    if opts.download_only != cloned.download_only {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_debug_format() -> TestResult {
    let opts = UpgradeOptions::default();
    let debug_str = alloc::format!("{:?}", opts);
    if !debug_str.contains("UpgradeOptions") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_no_deps() -> TestResult {
    let opts = UpgradeOptions { no_deps: true, ..Default::default() };
    if !opts.no_deps {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_no_scripts() -> TestResult {
    let opts = UpgradeOptions { no_scripts: true, ..Default::default() };
    if !opts.no_scripts {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_download_only() -> TestResult {
    let opts = UpgradeOptions { download_only: true, ..Default::default() };
    if !opts.download_only {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_options_all_true() -> TestResult {
    let opts = InstallOptions {
        force: true,
        no_deps: true,
        no_scripts: true,
        download_only: true,
        as_dependency: true,
        reinstall: true,
    };
    if !opts.force {
        return TestResult::Fail;
    }
    if !opts.no_deps {
        return TestResult::Fail;
    }
    if !opts.no_scripts {
        return TestResult::Fail;
    }
    if !opts.download_only {
        return TestResult::Fail;
    }
    if !opts.as_dependency {
        return TestResult::Fail;
    }
    if !opts.reinstall {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_options_all_true() -> TestResult {
    let opts = RemoveOptions { recursive: true, no_scripts: true, keep_config: true, purge: true };
    if !opts.recursive {
        return TestResult::Fail;
    }
    if !opts.no_scripts {
        return TestResult::Fail;
    }
    if !opts.keep_config {
        return TestResult::Fail;
    }
    if !opts.purge {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_upgrade_options_all_true() -> TestResult {
    let opts = UpgradeOptions { no_deps: true, no_scripts: true, download_only: true };
    if !opts.no_deps {
        return TestResult::Fail;
    }
    if !opts.no_scripts {
        return TestResult::Fail;
    }
    if !opts.download_only {
        return TestResult::Fail;
    }
    TestResult::Pass
}
