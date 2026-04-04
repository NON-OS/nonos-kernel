use crate::npkg::*;
use crate::npkg::installer::{InstallOptions, RemoveOptions, UpgradeOptions};

#[test]
fn test_install_options_default() {
    let opts = InstallOptions::default();
    assert!(!opts.force);
    assert!(!opts.no_deps);
    assert!(!opts.no_scripts);
    assert!(!opts.download_only);
    assert!(!opts.as_dependency);
    assert!(!opts.reinstall);
}

#[test]
fn test_install_options_clone() {
    let opts = InstallOptions {
        force: true,
        no_deps: false,
        no_scripts: true,
        download_only: false,
        as_dependency: true,
        reinstall: false,
    };
    let cloned = opts.clone();
    assert_eq!(opts.force, cloned.force);
    assert_eq!(opts.no_scripts, cloned.no_scripts);
    assert_eq!(opts.as_dependency, cloned.as_dependency);
}

#[test]
fn test_install_options_debug_format() {
    let opts = InstallOptions::default();
    let debug_str = alloc::format!("{:?}", opts);
    assert!(debug_str.contains("InstallOptions"));
}

#[test]
fn test_install_options_force() {
    let opts = InstallOptions {
        force: true,
        ..Default::default()
    };
    assert!(opts.force);
    assert!(!opts.no_deps);
}

#[test]
fn test_install_options_no_deps() {
    let opts = InstallOptions {
        no_deps: true,
        ..Default::default()
    };
    assert!(opts.no_deps);
}

#[test]
fn test_install_options_no_scripts() {
    let opts = InstallOptions {
        no_scripts: true,
        ..Default::default()
    };
    assert!(opts.no_scripts);
}

#[test]
fn test_install_options_download_only() {
    let opts = InstallOptions {
        download_only: true,
        ..Default::default()
    };
    assert!(opts.download_only);
}

#[test]
fn test_install_options_as_dependency() {
    let opts = InstallOptions {
        as_dependency: true,
        ..Default::default()
    };
    assert!(opts.as_dependency);
}

#[test]
fn test_install_options_reinstall() {
    let opts = InstallOptions {
        reinstall: true,
        ..Default::default()
    };
    assert!(opts.reinstall);
}

#[test]
fn test_remove_options_default() {
    let opts = RemoveOptions::default();
    assert!(!opts.recursive);
    assert!(!opts.no_scripts);
    assert!(opts.keep_config);
    assert!(!opts.purge);
}

#[test]
fn test_remove_options_clone() {
    let opts = RemoveOptions {
        recursive: true,
        no_scripts: false,
        keep_config: false,
        purge: true,
    };
    let cloned = opts.clone();
    assert_eq!(opts.recursive, cloned.recursive);
    assert_eq!(opts.purge, cloned.purge);
}

#[test]
fn test_remove_options_debug_format() {
    let opts = RemoveOptions::default();
    let debug_str = alloc::format!("{:?}", opts);
    assert!(debug_str.contains("RemoveOptions"));
}

#[test]
fn test_remove_options_recursive() {
    let opts = RemoveOptions {
        recursive: true,
        ..Default::default()
    };
    assert!(opts.recursive);
}

#[test]
fn test_remove_options_no_scripts() {
    let opts = RemoveOptions {
        no_scripts: true,
        ..Default::default()
    };
    assert!(opts.no_scripts);
}

#[test]
fn test_remove_options_keep_config() {
    let opts = RemoveOptions::default();
    assert!(opts.keep_config);

    let opts_purge = RemoveOptions {
        keep_config: false,
        ..Default::default()
    };
    assert!(!opts_purge.keep_config);
}

#[test]
fn test_remove_options_purge() {
    let opts = RemoveOptions {
        purge: true,
        ..Default::default()
    };
    assert!(opts.purge);
}

#[test]
fn test_upgrade_options_default() {
    let opts = UpgradeOptions::default();
    assert!(!opts.no_deps);
    assert!(!opts.no_scripts);
    assert!(!opts.download_only);
}

#[test]
fn test_upgrade_options_clone() {
    let opts = UpgradeOptions {
        no_deps: true,
        no_scripts: true,
        download_only: true,
    };
    let cloned = opts.clone();
    assert_eq!(opts.no_deps, cloned.no_deps);
    assert_eq!(opts.no_scripts, cloned.no_scripts);
    assert_eq!(opts.download_only, cloned.download_only);
}

#[test]
fn test_upgrade_options_debug_format() {
    let opts = UpgradeOptions::default();
    let debug_str = alloc::format!("{:?}", opts);
    assert!(debug_str.contains("UpgradeOptions"));
}

#[test]
fn test_upgrade_options_no_deps() {
    let opts = UpgradeOptions {
        no_deps: true,
        ..Default::default()
    };
    assert!(opts.no_deps);
}

#[test]
fn test_upgrade_options_no_scripts() {
    let opts = UpgradeOptions {
        no_scripts: true,
        ..Default::default()
    };
    assert!(opts.no_scripts);
}

#[test]
fn test_upgrade_options_download_only() {
    let opts = UpgradeOptions {
        download_only: true,
        ..Default::default()
    };
    assert!(opts.download_only);
}

#[test]
fn test_install_options_all_true() {
    let opts = InstallOptions {
        force: true,
        no_deps: true,
        no_scripts: true,
        download_only: true,
        as_dependency: true,
        reinstall: true,
    };
    assert!(opts.force);
    assert!(opts.no_deps);
    assert!(opts.no_scripts);
    assert!(opts.download_only);
    assert!(opts.as_dependency);
    assert!(opts.reinstall);
}

#[test]
fn test_remove_options_all_true() {
    let opts = RemoveOptions {
        recursive: true,
        no_scripts: true,
        keep_config: true,
        purge: true,
    };
    assert!(opts.recursive);
    assert!(opts.no_scripts);
    assert!(opts.keep_config);
    assert!(opts.purge);
}

#[test]
fn test_upgrade_options_all_true() {
    let opts = UpgradeOptions {
        no_deps: true,
        no_scripts: true,
        download_only: true,
    };
    assert!(opts.no_deps);
    assert!(opts.no_scripts);
    assert!(opts.download_only);
}
