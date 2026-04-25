use crate::npkg::types::*;
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_architecture_current() -> TestResult {
    let arch = Architecture::current();
    if arch != Architecture::X86_64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_x86_64() -> TestResult {
    let arch = Architecture::from_str("x86_64");
    if arch != Some(Architecture::X86_64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_amd64() -> TestResult {
    let arch = Architecture::from_str("amd64");
    if arch != Some(Architecture::X86_64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_aarch64() -> TestResult {
    let arch = Architecture::from_str("aarch64");
    if arch != Some(Architecture::Aarch64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_arm64() -> TestResult {
    let arch = Architecture::from_str("arm64");
    if arch != Some(Architecture::Aarch64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_any() -> TestResult {
    let arch = Architecture::from_str("any");
    if arch != Some(Architecture::Any) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_noarch() -> TestResult {
    let arch = Architecture::from_str("noarch");
    if arch != Some(Architecture::Any) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_from_str_invalid() -> TestResult {
    let arch = Architecture::from_str("invalid");
    if arch.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_as_str() -> TestResult {
    if Architecture::X86_64.as_str() != "x86_64" {
        return TestResult::Fail;
    }
    if Architecture::Aarch64.as_str() != "aarch64" {
        return TestResult::Fail;
    }
    if Architecture::Any.as_str() != "any" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_is_compatible_any() -> TestResult {
    if !Architecture::Any.is_compatible(Architecture::X86_64) {
        return TestResult::Fail;
    }
    if !Architecture::Any.is_compatible(Architecture::Aarch64) {
        return TestResult::Fail;
    }
    if !Architecture::Any.is_compatible(Architecture::Any) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_is_compatible_same() -> TestResult {
    if !Architecture::X86_64.is_compatible(Architecture::X86_64) {
        return TestResult::Fail;
    }
    if !Architecture::Aarch64.is_compatible(Architecture::Aarch64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_is_compatible_different() -> TestResult {
    if Architecture::X86_64.is_compatible(Architecture::Aarch64) {
        return TestResult::Fail;
    }
    if Architecture::Aarch64.is_compatible(Architecture::X86_64) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_binary() -> TestResult {
    if PackageKind::from_str("binary") != Some(PackageKind::Binary) {
        return TestResult::Fail;
    }
    if PackageKind::from_str("bin") != Some(PackageKind::Binary) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_library() -> TestResult {
    if PackageKind::from_str("library") != Some(PackageKind::Library) {
        return TestResult::Fail;
    }
    if PackageKind::from_str("lib") != Some(PackageKind::Library) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_data() -> TestResult {
    if PackageKind::from_str("data") != Some(PackageKind::Data) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_font() -> TestResult {
    if PackageKind::from_str("font") != Some(PackageKind::Font) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_theme() -> TestResult {
    if PackageKind::from_str("theme") != Some(PackageKind::Theme) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_driver() -> TestResult {
    if PackageKind::from_str("driver") != Some(PackageKind::Driver) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_service() -> TestResult {
    if PackageKind::from_str("service") != Some(PackageKind::Service) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_meta() -> TestResult {
    if PackageKind::from_str("meta") != Some(PackageKind::Meta) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_from_str_invalid() -> TestResult {
    if PackageKind::from_str("invalid").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_as_str() -> TestResult {
    if PackageKind::Binary.as_str() != "binary" {
        return TestResult::Fail;
    }
    if PackageKind::Library.as_str() != "library" {
        return TestResult::Fail;
    }
    if PackageKind::Data.as_str() != "data" {
        return TestResult::Fail;
    }
    if PackageKind::Font.as_str() != "font" {
        return TestResult::Fail;
    }
    if PackageKind::Theme.as_str() != "theme" {
        return TestResult::Fail;
    }
    if PackageKind::Driver.as_str() != "driver" {
        return TestResult::Fail;
    }
    if PackageKind::Service.as_str() != "service" {
        return TestResult::Fail;
    }
    if PackageKind::Meta.as_str() != "meta" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_state_variants() -> TestResult {
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
    if states.len() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_runtime() -> TestResult {
    if DependencyKind::from_str("runtime") != Some(DependencyKind::Runtime) {
        return TestResult::Fail;
    }
    if DependencyKind::from_str("depends") != Some(DependencyKind::Runtime) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_build() -> TestResult {
    if DependencyKind::from_str("build") != Some(DependencyKind::Build) {
        return TestResult::Fail;
    }
    if DependencyKind::from_str("makedepends") != Some(DependencyKind::Build) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_optional() -> TestResult {
    if DependencyKind::from_str("optional") != Some(DependencyKind::Optional) {
        return TestResult::Fail;
    }
    if DependencyKind::from_str("optdepends") != Some(DependencyKind::Optional) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_conflict() -> TestResult {
    if DependencyKind::from_str("conflict") != Some(DependencyKind::Conflict) {
        return TestResult::Fail;
    }
    if DependencyKind::from_str("conflicts") != Some(DependencyKind::Conflict) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_replace() -> TestResult {
    if DependencyKind::from_str("replace") != Some(DependencyKind::Replace) {
        return TestResult::Fail;
    }
    if DependencyKind::from_str("replaces") != Some(DependencyKind::Replace) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_provide() -> TestResult {
    if DependencyKind::from_str("provide") != Some(DependencyKind::Provide) {
        return TestResult::Fail;
    }
    if DependencyKind::from_str("provides") != Some(DependencyKind::Provide) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_from_str_invalid() -> TestResult {
    if DependencyKind::from_str("invalid").is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_permissions_default() -> TestResult {
    let perms = FilePermissions::default();
    if perms.mode != 0o644 {
        return TestResult::Fail;
    }
    if perms.uid != 0 {
        return TestResult::Fail;
    }
    if perms.gid != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_permissions_executable() -> TestResult {
    let perms = FilePermissions::executable();
    if perms.mode != 0o755 {
        return TestResult::Fail;
    }
    if perms.uid != 0 {
        return TestResult::Fail;
    }
    if perms.gid != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_permissions_directory() -> TestResult {
    let perms = FilePermissions::directory();
    if perms.mode != 0o755 {
        return TestResult::Fail;
    }
    if perms.uid != 0 {
        return TestResult::Fail;
    }
    if perms.gid != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_reason_variants() -> TestResult {
    let reasons = [InstallReason::Explicit, InstallReason::Dependency, InstallReason::Optional];
    if reasons.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_id_new() -> TestResult {
    let version = PackageVersion::new(1, 2, 3);
    let id = PackageId::new(alloc::string::String::from("testpkg"), version.clone());
    if id.name != "testpkg" {
        return TestResult::Fail;
    }
    if id.version != version {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_id_parse() -> TestResult {
    let id = PackageId::parse("testpkg-1.2.3");
    if id.is_none() {
        return TestResult::Fail;
    }
    let id = id.unwrap();
    if id.name != "testpkg" {
        return TestResult::Fail;
    }
    if id.version.major != 1 {
        return TestResult::Fail;
    }
    if id.version.minor != 2 {
        return TestResult::Fail;
    }
    if id.version.patch != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_id_parse_with_hyphen_in_name() -> TestResult {
    let id = PackageId::parse("my-test-pkg-2.0.0");
    if id.is_none() {
        return TestResult::Fail;
    }
    let id = id.unwrap();
    if id.name != "my-test-pkg" {
        return TestResult::Fail;
    }
    if id.version.major != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_id_parse_invalid() -> TestResult {
    let id = PackageId::parse("invalid");
    if id.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_architecture_default() -> TestResult {
    let arch: Architecture = Default::default();
    if arch != Architecture::X86_64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_package_kind_default() -> TestResult {
    let kind: PackageKind = Default::default();
    if kind != PackageKind::Binary {
        return TestResult::Fail;
    }
    TestResult::Pass
}
