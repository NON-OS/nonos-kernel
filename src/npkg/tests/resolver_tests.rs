// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::npkg::resolver::types::{ResolutionResult, ResolutionPlan};
use crate::npkg::types::{Package, PackageMeta, PackageVersion, InstallReason, Architecture, PackageKind};
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
            kind: PackageKind::Application,
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

#[test]
fn test_resolution_result_new() {
    let result = ResolutionResult::new();
    assert!(result.to_install.is_empty());
    assert!(result.to_upgrade.is_empty());
    assert!(result.to_remove.is_empty());
    assert!(result.satisfied.is_empty());
    assert!(result.optional.is_empty());
}

#[test]
fn test_resolution_result_is_empty_true() {
    let result = ResolutionResult::new();
    assert!(result.is_empty());
}

#[test]
fn test_resolution_result_is_empty_with_install() {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("test", 1, 0, 0);
    result.to_install.push((pkg, InstallReason::Explicit));
    assert!(!result.is_empty());
}

#[test]
fn test_resolution_result_is_empty_with_upgrade() {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("test", 2, 0, 0);
    let old_version = PackageVersion::new(1, 0, 0);
    result.to_upgrade.push((pkg, old_version));
    assert!(!result.is_empty());
}

#[test]
fn test_resolution_result_is_empty_with_remove() {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::from("removed-pkg"));
    assert!(!result.is_empty());
}

#[test]
fn test_resolution_result_total_packages_empty() {
    let result = ResolutionResult::new();
    assert_eq!(result.total_packages(), 0);
}

#[test]
fn test_resolution_result_total_packages_with_install() {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("pkg1", 1, 0, 0);
    result.to_install.push((pkg, InstallReason::Explicit));
    assert_eq!(result.total_packages(), 1);
}

#[test]
fn test_resolution_result_total_packages_with_upgrade() {
    let mut result = ResolutionResult::new();
    let pkg = make_test_package("pkg1", 2, 0, 0);
    result.to_upgrade.push((pkg, PackageVersion::new(1, 0, 0)));
    assert_eq!(result.total_packages(), 1);
}

#[test]
fn test_resolution_result_total_packages_combined() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("pkg1", 1, 0, 0), InstallReason::Explicit));
    result.to_install.push((make_test_package("pkg2", 1, 0, 0), InstallReason::Dependency));
    result.to_upgrade.push((make_test_package("pkg3", 2, 0, 0), PackageVersion::new(1, 0, 0)));
    assert_eq!(result.total_packages(), 3);
}

#[test]
fn test_resolution_result_total_packages_ignores_remove() {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::from("removed1"));
    result.to_remove.push(String::from("removed2"));
    assert_eq!(result.total_packages(), 0);
}

#[test]
fn test_resolution_result_clone() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("test", 1, 0, 0), InstallReason::Explicit));
    result.to_remove.push(String::from("old-pkg"));
    let cloned = result.clone();
    assert_eq!(result.to_install.len(), cloned.to_install.len());
    assert_eq!(result.to_remove.len(), cloned.to_remove.len());
}

#[test]
fn test_resolution_result_with_satisfied() {
    let mut result = ResolutionResult::new();
    result.satisfied.push(String::from("already-installed"));
    assert!(result.is_empty());
    assert_eq!(result.satisfied.len(), 1);
}

#[test]
fn test_resolution_result_with_optional() {
    let mut result = ResolutionResult::new();
    result.optional.push((String::from("optional-pkg"), String::from("for feature X")));
    assert!(result.is_empty());
    assert_eq!(result.optional.len(), 1);
}

#[test]
fn test_resolution_result_install_reasons() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("app", 1, 0, 0), InstallReason::Explicit));
    result.to_install.push((make_test_package("lib", 1, 0, 0), InstallReason::Dependency));
    result.to_install.push((make_test_package("opt", 1, 0, 0), InstallReason::Optional));
    assert_eq!(result.to_install[0].1, InstallReason::Explicit);
    assert_eq!(result.to_install[1].1, InstallReason::Dependency);
    assert_eq!(result.to_install[2].1, InstallReason::Optional);
}

#[test]
fn test_resolution_plan_fields() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: 1024,
        install_size: 2048,
        remove_size: 512,
    };
    assert_eq!(plan.download_size, 1024);
    assert_eq!(plan.install_size, 2048);
    assert_eq!(plan.remove_size, 512);
}

#[test]
fn test_resolution_plan_empty_result() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: 0,
        install_size: 0,
        remove_size: 0,
    };
    assert!(plan.result.is_empty());
    assert_eq!(plan.download_size, 0);
}

#[test]
fn test_resolution_plan_with_installs() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("pkg1", 1, 0, 0), InstallReason::Explicit));
    let plan = ResolutionPlan {
        result,
        download_size: 512,
        install_size: 1024,
        remove_size: 0,
    };
    assert_eq!(plan.result.total_packages(), 1);
    assert_eq!(plan.download_size, 512);
}

#[test]
fn test_resolution_plan_with_removes() {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::from("old-pkg"));
    let plan = ResolutionPlan {
        result,
        download_size: 0,
        install_size: 0,
        remove_size: 4096,
    };
    assert_eq!(plan.result.to_remove.len(), 1);
    assert_eq!(plan.remove_size, 4096);
}

#[test]
fn test_resolution_plan_clone() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("pkg", 1, 0, 0), InstallReason::Explicit));
    let plan = ResolutionPlan {
        result,
        download_size: 100,
        install_size: 200,
        remove_size: 50,
    };
    let cloned = plan.clone();
    assert_eq!(plan.download_size, cloned.download_size);
    assert_eq!(plan.install_size, cloned.install_size);
    assert_eq!(plan.remove_size, cloned.remove_size);
}

#[test]
fn test_resolution_plan_large_sizes() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: u64::MAX,
        install_size: u64::MAX,
        remove_size: u64::MAX,
    };
    assert_eq!(plan.download_size, u64::MAX);
    assert_eq!(plan.install_size, u64::MAX);
    assert_eq!(plan.remove_size, u64::MAX);
}

#[test]
fn test_resolution_plan_net_size_increase() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: 1000,
        install_size: 2000,
        remove_size: 500,
    };
    let net_change = plan.install_size as i64 - plan.remove_size as i64;
    assert_eq!(net_change, 1500);
}

#[test]
fn test_resolution_plan_net_size_decrease() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: 100,
        install_size: 500,
        remove_size: 1000,
    };
    let net_change = plan.install_size as i64 - plan.remove_size as i64;
    assert_eq!(net_change, -500);
}

#[test]
fn test_install_reason_explicit() {
    let reason = InstallReason::Explicit;
    assert_eq!(reason, InstallReason::Explicit);
}

#[test]
fn test_install_reason_dependency() {
    let reason = InstallReason::Dependency;
    assert_eq!(reason, InstallReason::Dependency);
}

#[test]
fn test_install_reason_optional() {
    let reason = InstallReason::Optional;
    assert_eq!(reason, InstallReason::Optional);
}

#[test]
fn test_install_reason_clone() {
    let reason = InstallReason::Explicit;
    let cloned = reason.clone();
    assert_eq!(reason, cloned);
}

#[test]
fn test_install_reason_copy() {
    let reason = InstallReason::Dependency;
    let copied = reason;
    assert_eq!(reason, copied);
}

#[test]
fn test_install_reason_equality() {
    assert_eq!(InstallReason::Explicit, InstallReason::Explicit);
    assert_ne!(InstallReason::Explicit, InstallReason::Dependency);
    assert_ne!(InstallReason::Dependency, InstallReason::Optional);
}

#[test]
fn test_resolution_result_multiple_satisfied() {
    let mut result = ResolutionResult::new();
    result.satisfied.push(String::from("pkg1"));
    result.satisfied.push(String::from("pkg2"));
    result.satisfied.push(String::from("pkg3"));
    assert_eq!(result.satisfied.len(), 3);
    assert!(result.is_empty());
}

#[test]
fn test_resolution_result_complex_scenario() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("new-app", 1, 0, 0), InstallReason::Explicit));
    result.to_install.push((make_test_package("new-lib", 2, 3, 4), InstallReason::Dependency));
    result.to_upgrade.push((make_test_package("existing", 2, 0, 0), PackageVersion::new(1, 5, 0)));
    result.to_remove.push(String::from("obsolete"));
    result.satisfied.push(String::from("already-ok"));
    result.optional.push((String::from("opt-feature"), String::from("enhances something")));
    assert!(!result.is_empty());
    assert_eq!(result.total_packages(), 3);
    assert_eq!(result.to_remove.len(), 1);
    assert_eq!(result.satisfied.len(), 1);
    assert_eq!(result.optional.len(), 1);
}

#[test]
fn test_resolution_result_debug() {
    let result = ResolutionResult::new();
    let debug_str = alloc::format!("{:?}", result);
    assert!(debug_str.contains("ResolutionResult"));
}

#[test]
fn test_resolution_plan_debug() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: 0,
        install_size: 0,
        remove_size: 0,
    };
    let debug_str = alloc::format!("{:?}", plan);
    assert!(debug_str.contains("ResolutionPlan"));
}

#[test]
fn test_resolution_result_upgrade_versions() {
    let mut result = ResolutionResult::new();
    let new_pkg = make_test_package("test", 2, 0, 0);
    let old_version = PackageVersion::new(1, 0, 0);
    result.to_upgrade.push((new_pkg, old_version.clone()));
    assert_eq!(result.to_upgrade[0].1.major, 1);
    assert_eq!(result.to_upgrade[0].0.meta.version.major, 2);
}

#[test]
fn test_resolution_plan_access_inner_result() {
    let mut result = ResolutionResult::new();
    result.to_install.push((make_test_package("inner", 1, 0, 0), InstallReason::Explicit));
    let plan = ResolutionPlan {
        result,
        download_size: 100,
        install_size: 200,
        remove_size: 0,
    };
    assert_eq!(plan.result.to_install.len(), 1);
    assert_eq!(plan.result.to_install[0].0.meta.name, "inner");
}

#[test]
fn test_resolution_result_empty_strings() {
    let mut result = ResolutionResult::new();
    result.to_remove.push(String::new());
    result.satisfied.push(String::new());
    assert!(!result.is_empty());
    assert_eq!(result.to_remove[0], "");
}

#[test]
fn test_resolution_plan_zero_download_nonzero_install() {
    let result = ResolutionResult::new();
    let plan = ResolutionPlan {
        result,
        download_size: 0,
        install_size: 1000,
        remove_size: 0,
    };
    assert_eq!(plan.download_size, 0);
    assert_eq!(plan.install_size, 1000);
}

