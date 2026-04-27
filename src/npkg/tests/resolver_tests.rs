// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::npkg::resolver::types::{ResolutionPlan, ResolutionResult};
use crate::npkg::types::{
    Architecture, InstallReason, Package, PackageKind, PackageMeta, PackageVersion,
};
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec::Vec;

fn make_test_package(name: &str, major: u32, minor: u32, patch: u32) -> Package {
    Package {
        meta: PackageMeta {
            name: String::from(name),
            version: PackageVersion::new(major, minor, patch),
            description: String::from("Test package"),
            long_description: None,
            homepage: None,
            license: String::from("MIT"),
            maintainer: None,
            architecture: Architecture::X86_64,
            kind: PackageKind::Binary,
            size_installed: 1024,
            size_download: 512,
            checksum_blake3: [0u8; 32],
            signature: None,
        },
        dependencies: Vec::new(),
        files: Vec::new(),
        install_script: None,
        remove_script: None,
    }
}

pub(crate) fn test_resolution_result_new() -> TestResult {
    let result = ResolutionResult::new();
    if !result.to_install.is_empty() {
        return TestResult::Fail;
    }
    if !result.to_upgrade.is_empty() {
        return TestResult::Fail;
    }
    if !result.to_remove.is_empty() {
        return TestResult::Fail;
    }
    if !result.satisfied.is_empty() {
        return TestResult::Fail;
    }
    if !result.optional.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_is_empty_true() -> TestResult {
    let result = ResolutionResult::new();
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_is_empty_with_install() -> TestResult {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("test", 1, 0, 0);
    result.to_install.push((pkg, InstallReason::Explicit));
    if result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_is_empty_with_upgrade() -> TestResult {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("test", 2, 0, 0);
    let old_version = PackageVersion::new(1, 0, 0);
    result.to_upgrade.push((pkg, old_version));
    if result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_is_empty_with_remove() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::from("removed-pkg"));
    if result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_total_packages_empty() -> TestResult {
    let result = ResolutionResult::new();
    if result.total_packages() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_total_packages_with_install() -> TestResult {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("pkg1", 1, 0, 0);
    result.to_install.push((pkg, InstallReason::Explicit));
    if result.total_packages() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_total_packages_with_upgrade() -> TestResult {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("pkg1", 2, 0, 0);
    result.to_upgrade.push((pkg, PackageVersion::new(1, 0, 0)));
    if result.total_packages() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_total_packages_combined() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("pkg1", 1, 0, 0), InstallReason::Explicit));
    result.to_install.push((make_test_package("pkg2", 1, 0, 0), InstallReason::Dependency));
    result.to_upgrade.push((make_test_package("pkg3", 2, 0, 0), PackageVersion::new(1, 0, 0)));
    if result.total_packages() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_total_packages_ignores_remove() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::from("removed1"));
    result.to_remove.push(String::from("removed2"));
    if result.total_packages() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_clone() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("test", 1, 0, 0), InstallReason::Explicit));
    result.to_remove.push(String::from("old-pkg"));
    let cloned = result.clone();
    if result.to_install.len() != cloned.to_install.len() {
        return TestResult::Fail;
    }
    if result.to_remove.len() != cloned.to_remove.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_with_satisfied() -> TestResult {
    let mut result = ResolutionResult::new();
    result.satisfied.push(String::from("already-installed"));
    if !result.is_empty() {
        return TestResult::Fail;
    }
    if result.satisfied.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_with_optional() -> TestResult {
    let mut result = ResolutionResult::new();
    result.optional.push((String::from("optional-pkg"), String::from("for feature X")));
    if !result.is_empty() {
        return TestResult::Fail;
    }
    if result.optional.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_install_reasons() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("app", 1, 0, 0), InstallReason::Explicit));
    result.to_install.push((make_test_package("lib", 1, 0, 0), InstallReason::Dependency));
    result.to_install.push((make_test_package("opt", 1, 0, 0), InstallReason::Optional));
    if result.to_install[0].1 != InstallReason::Explicit {
        return TestResult::Fail;
    }
    if result.to_install[1].1 != InstallReason::Dependency {
        return TestResult::Fail;
    }
    if result.to_install[2].1 != InstallReason::Optional {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_fields() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan { result, download_size: 1024, install_size: 2048, remove_size: 512 };
    if plan.download_size != 1024 {
        return TestResult::Fail;
    }
    if plan.install_size != 2048 {
        return TestResult::Fail;
    }
    if plan.remove_size != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_empty_result() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan { result, download_size: 0, install_size: 0, remove_size: 0 };
    if !plan.result.is_empty() {
        return TestResult::Fail;
    }
    if plan.download_size != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_with_installs() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("pkg1", 1, 0, 0), InstallReason::Explicit));
    let plan = ResolutionPlan { result, download_size: 512, install_size: 1024, remove_size: 0 };
    if plan.result.total_packages() != 1 {
        return TestResult::Fail;
    }
    if plan.download_size != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_with_removes() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::from("old-pkg"));
    let plan = ResolutionPlan { result, download_size: 0, install_size: 0, remove_size: 4096 };
    if plan.result.to_remove.len() != 1 {
        return TestResult::Fail;
    }
    if plan.remove_size != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_clone() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("pkg", 1, 0, 0), InstallReason::Explicit));
    let plan = ResolutionPlan { result, download_size: 100, install_size: 200, remove_size: 50 };
    let cloned = plan.clone();
    if plan.download_size != cloned.download_size {
        return TestResult::Fail;
    }
    if plan.install_size != cloned.install_size {
        return TestResult::Fail;
    }
    if plan.remove_size != cloned.remove_size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_large_sizes() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: u64::MAX,
        install_size: u64::MAX,
        remove_size: u64::MAX,
    };
    if plan.download_size != u64::MAX {
        return TestResult::Fail;
    }
    if plan.install_size != u64::MAX {
        return TestResult::Fail;
    }
    if plan.remove_size != u64::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_net_size_increase() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan { result, download_size: 1000, install_size: 2000, remove_size: 500 };
    let net_change = plan.install_size as i64 - plan.remove_size as i64;
    if net_change != 1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_net_size_decrease() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan { result, download_size: 100, install_size: 500, remove_size: 1000 };
    let net_change = plan.install_size as i64 - plan.remove_size as i64;
    if net_change != -500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_explicit() -> TestResult {
    let reason = InstallReason::Explicit;
    if reason != InstallReason::Explicit {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_dependency() -> TestResult {
    let reason = InstallReason::Dependency;
    if reason != InstallReason::Dependency {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_optional() -> TestResult {
    let reason = InstallReason::Optional;
    if reason != InstallReason::Optional {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_clone() -> TestResult {
    let reason = InstallReason::Explicit;
    let cloned = reason.clone();
    if reason != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_copy() -> TestResult {
    let reason = InstallReason::Dependency;
    let copied = reason;
    if reason != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_equality() -> TestResult {
    if InstallReason::Explicit != InstallReason::Explicit {
        return TestResult::Fail;
    }
    if InstallReason::Explicit == InstallReason::Dependency {
        return TestResult::Fail;
    }
    if InstallReason::Dependency == InstallReason::Optional {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_multiple_satisfied() -> TestResult {
    let mut result = ResolutionResult::new();
    result.satisfied.push(String::from("pkg1"));
    result.satisfied.push(String::from("pkg2"));
    result.satisfied.push(String::from("pkg3"));
    if result.satisfied.len() != 3 {
        return TestResult::Fail;
    }
    if !result.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_complex_scenario() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("new-app", 1, 0, 0), InstallReason::Explicit));
    result.to_install.push((make_test_package("new-lib", 2, 3, 4), InstallReason::Dependency));
    result.to_upgrade.push((make_test_package("existing", 2, 0, 0), PackageVersion::new(1, 5, 0)));
    result.to_remove.push(String::from("obsolete"));
    result.satisfied.push(String::from("already-ok"));
    result.optional.push((String::from("opt-feature"), String::from("enhances something")));
    if result.is_empty() {
        return TestResult::Fail;
    }
    if result.total_packages() != 3 {
        return TestResult::Fail;
    }
    if result.to_remove.len() != 1 {
        return TestResult::Fail;
    }
    if result.satisfied.len() != 1 {
        return TestResult::Fail;
    }
    if result.optional.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_debug() -> TestResult {
    let result = ResolutionResult::new();
    let debug_str = alloc::format!("{:?}", result);
    if !debug_str.contains("ResolutionResult") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_debug() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan { result, download_size: 0, install_size: 0, remove_size: 0 };
    let debug_str = alloc::format!("{:?}", plan);
    if !debug_str.contains("ResolutionPlan") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_upgrade_versions() -> TestResult {
    let mut result = ResolutionResult::new();
    let new_pkg = make_test_package("test", 2, 0, 0);
    let old_version = PackageVersion::new(1, 0, 0);
    result.to_upgrade.push((new_pkg, old_version.clone()));
    if result.to_upgrade[0].1.major != 1 {
        return TestResult::Fail;
    }
    if result.to_upgrade[0].0.meta.version.major != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_access_inner_result() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("inner", 1, 0, 0), InstallReason::Explicit));
    let plan = ResolutionPlan { result, download_size: 100, install_size: 200, remove_size: 0 };
    if plan.result.to_install.len() != 1 {
        return TestResult::Fail;
    }
    if plan.result.to_install[0].0.meta.name != "inner" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_result_empty_strings() -> TestResult {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::new());
    result.satisfied.push(String::new());
    if result.is_empty() {
        return TestResult::Fail;
    }
    if result.to_remove[0] != "" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_resolution_plan_zero_download_nonzero_install() -> TestResult {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan { result, download_size: 0, install_size: 1000, remove_size: 0 };
    if plan.download_size != 0 {
        return TestResult::Fail;
    }
    if plan.install_size != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
