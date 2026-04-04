use crate::npkg::*;
use crate::npkg::types::*;

#[test]
fn test_architecture_current() {
    let arch = Architecture::current();
    assert_eq!(arch, Architecture::X86_64);
}

#[test]
fn test_architecture_from_str_x86_64() {
    let arch = Architecture::from_str("x86_64");
    assert_eq!(arch, Some(Architecture::X86_64));
}

#[test]
fn test_architecture_from_str_amd64() {
    let arch = Architecture::from_str("amd64");
    assert_eq!(arch, Some(Architecture::X86_64));
}

#[test]
fn test_architecture_from_str_aarch64() {
    let arch = Architecture::from_str("aarch64");
    assert_eq!(arch, Some(Architecture::Aarch64));
}

#[test]
fn test_architecture_from_str_arm64() {
    let arch = Architecture::from_str("arm64");
    assert_eq!(arch, Some(Architecture::Aarch64));
}

#[test]
fn test_architecture_from_str_any() {
    let arch = Architecture::from_str("any");
    assert_eq!(arch, Some(Architecture::Any));
}

#[test]
fn test_architecture_from_str_noarch() {
    let arch = Architecture::from_str("noarch");
    assert_eq!(arch, Some(Architecture::Any));
}

#[test]
fn test_architecture_from_str_invalid() {
    let arch = Architecture::from_str("invalid");
    assert!(arch.is_none());
}

#[test]
fn test_architecture_as_str() {
    assert_eq!(Architecture::X86_64.as_str(), "x86_64");
    assert_eq!(Architecture::Aarch64.as_str(), "aarch64");
    assert_eq!(Architecture::Any.as_str(), "any");
}

#[test]
fn test_architecture_is_compatible_any() {
    assert!(Architecture::Any.is_compatible(Architecture::X86_64));
    assert!(Architecture::Any.is_compatible(Architecture::Aarch64));
    assert!(Architecture::Any.is_compatible(Architecture::Any));
}

#[test]
fn test_architecture_is_compatible_same() {
    assert!(Architecture::X86_64.is_compatible(Architecture::X86_64));
    assert!(Architecture::Aarch64.is_compatible(Architecture::Aarch64));
}

#[test]
fn test_architecture_is_compatible_different() {
    assert!(!Architecture::X86_64.is_compatible(Architecture::Aarch64));
    assert!(!Architecture::Aarch64.is_compatible(Architecture::X86_64));
}

#[test]
fn test_package_kind_from_str_binary() {
    assert_eq!(PackageKind::from_str("binary"), Some(PackageKind::Binary));
    assert_eq!(PackageKind::from_str("bin"), Some(PackageKind::Binary));
}

#[test]
fn test_package_kind_from_str_library() {
    assert_eq!(PackageKind::from_str("library"), Some(PackageKind::Library));
    assert_eq!(PackageKind::from_str("lib"), Some(PackageKind::Library));
}

#[test]
fn test_package_kind_from_str_data() {
    assert_eq!(PackageKind::from_str("data"), Some(PackageKind::Data));
}

#[test]
fn test_package_kind_from_str_font() {
    assert_eq!(PackageKind::from_str("font"), Some(PackageKind::Font));
}

#[test]
fn test_package_kind_from_str_theme() {
    assert_eq!(PackageKind::from_str("theme"), Some(PackageKind::Theme));
}

#[test]
fn test_package_kind_from_str_driver() {
    assert_eq!(PackageKind::from_str("driver"), Some(PackageKind::Driver));
}

#[test]
fn test_package_kind_from_str_service() {
    assert_eq!(PackageKind::from_str("service"), Some(PackageKind::Service));
}

#[test]
fn test_package_kind_from_str_meta() {
    assert_eq!(PackageKind::from_str("meta"), Some(PackageKind::Meta));
}

#[test]
fn test_package_kind_from_str_invalid() {
    assert!(PackageKind::from_str("invalid").is_none());
}

#[test]
fn test_package_kind_as_str() {
    assert_eq!(PackageKind::Binary.as_str(), "binary");
    assert_eq!(PackageKind::Library.as_str(), "library");
    assert_eq!(PackageKind::Data.as_str(), "data");
    assert_eq!(PackageKind::Font.as_str(), "font");
    assert_eq!(PackageKind::Theme.as_str(), "theme");
    assert_eq!(PackageKind::Driver.as_str(), "driver");
    assert_eq!(PackageKind::Service.as_str(), "service");
    assert_eq!(PackageKind::Meta.as_str(), "meta");
}

#[test]
fn test_package_state_variants() {
    let states = [
        PackageState::Available,
        PackageState::Downloading,
        PackageState::Downloaded,
        PackageState::Installing,
        PackageState::Installed,
        PackageState::Removing,
        PackageState::Broken,
        PackageState::OnHold,
    ];
    assert_eq!(states.len(), 8);
}

#[test]
fn test_dependency_kind_from_str_runtime() {
    assert_eq!(DependencyKind::from_str("runtime"), Some(DependencyKind::Runtime));
    assert_eq!(DependencyKind::from_str("depends"), Some(DependencyKind::Runtime));
}

#[test]
fn test_dependency_kind_from_str_build() {
    assert_eq!(DependencyKind::from_str("build"), Some(DependencyKind::Build));
    assert_eq!(DependencyKind::from_str("makedepends"), Some(DependencyKind::Build));
}

#[test]
fn test_dependency_kind_from_str_optional() {
    assert_eq!(DependencyKind::from_str("optional"), Some(DependencyKind::Optional));
    assert_eq!(DependencyKind::from_str("optdepends"), Some(DependencyKind::Optional));
}

#[test]
fn test_dependency_kind_from_str_conflict() {
    assert_eq!(DependencyKind::from_str("conflict"), Some(DependencyKind::Conflict));
    assert_eq!(DependencyKind::from_str("conflicts"), Some(DependencyKind::Conflict));
}

#[test]
fn test_dependency_kind_from_str_replace() {
    assert_eq!(DependencyKind::from_str("replace"), Some(DependencyKind::Replace));
    assert_eq!(DependencyKind::from_str("replaces"), Some(DependencyKind::Replace));
}

#[test]
fn test_dependency_kind_from_str_provide() {
    assert_eq!(DependencyKind::from_str("provide"), Some(DependencyKind::Provide));
    assert_eq!(DependencyKind::from_str("provides"), Some(DependencyKind::Provide));
}

#[test]
fn test_dependency_kind_from_str_invalid() {
    assert!(DependencyKind::from_str("invalid").is_none());
}

#[test]
fn test_file_permissions_default() {
    let perms = FilePermissions::default();
    assert_eq!(perms.mode, 0o644);
    assert_eq!(perms.uid, 0);
    assert_eq!(perms.gid, 0);
}

#[test]
fn test_file_permissions_executable() {
    let perms = FilePermissions::executable();
    assert_eq!(perms.mode, 0o755);
    assert_eq!(perms.uid, 0);
    assert_eq!(perms.gid, 0);
}

#[test]
fn test_file_permissions_directory() {
    let perms = FilePermissions::directory();
    assert_eq!(perms.mode, 0o755);
    assert_eq!(perms.uid, 0);
    assert_eq!(perms.gid, 0);
}

#[test]
fn test_install_reason_variants() {
    let reasons = [
        InstallReason::Explicit,
        InstallReason::Dependency,
        InstallReason::Optional,
    ];
    assert_eq!(reasons.len(), 3);
}

#[test]
fn test_package_id_new() {
    let version = PackageVersion::new(1, 2, 3);
    let id = PackageId::new(alloc::string::String::from("testpkg"), version.clone());
    assert_eq!(id.name, "testpkg");
    assert_eq!(id.version, version);
}

#[test]
fn test_package_id_parse() {
    let id = PackageId::parse("testpkg-1.2.3");
    assert!(id.is_some());
    let id = id.unwrap();
    assert_eq!(id.name, "testpkg");
    assert_eq!(id.version.major, 1);
    assert_eq!(id.version.minor, 2);
    assert_eq!(id.version.patch, 3);
}

#[test]
fn test_package_id_parse_with_hyphen_in_name() {
    let id = PackageId::parse("my-test-pkg-2.0.0");
    assert!(id.is_some());
    let id = id.unwrap();
    assert_eq!(id.name, "my-test-pkg");
    assert_eq!(id.version.major, 2);
}

#[test]
fn test_package_id_parse_invalid() {
    let id = PackageId::parse("invalid");
    assert!(id.is_none());
}

#[test]
fn test_architecture_default() {
    let arch: Architecture = Default::default();
    assert_eq!(arch, Architecture::X86_64);
}

#[test]
fn test_package_kind_default() {
    let kind: PackageKind = Default::default();
    assert_eq!(kind, PackageKind::Binary);
}
