use crate::npkg::types::{
    Architecture, DependencyKind, PackageKind, PackageVersion, VersionRequirement,
};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_manifest_builder_new() -> TestResult {
    let builder = ManifestBuilder::new();
    let result = builder.name("test").version(PackageVersion::new(1, 0, 0)).build();
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_missing_name() -> TestResult {
    let builder = ManifestBuilder::new();
    let result = builder.version(PackageVersion::new(1, 0, 0)).build();
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_missing_version() -> TestResult {
    let builder = ManifestBuilder::new();
    let result = builder.name("test").build();
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_full() -> TestResult {
    let manifest = ManifestBuilder::new()
        .name("testpkg")
        .version(PackageVersion::new(1, 2, 3))
        .description("A test package")
        .license("MIT")
        .architecture(Architecture::X86_64)
        .kind(PackageKind::Binary)
        .build()
        .unwrap();

    if manifest.package.meta.name != "testpkg" {
        return TestResult::Fail;
    }
    if manifest.package.meta.version.major != 1 {
        return TestResult::Fail;
    }
    if manifest.package.meta.description != "A test package" {
        return TestResult::Fail;
    }
    if manifest.package.meta.license != "MIT" {
        return TestResult::Fail;
    }
    if manifest.package.meta.architecture != Architecture::X86_64 {
        return TestResult::Fail;
    }
    if manifest.package.meta.kind != PackageKind::Binary {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_default_license() -> TestResult {
    let manifest =
        ManifestBuilder::new().name("test").version(PackageVersion::new(1, 0, 0)).build().unwrap();

    if manifest.package.meta.license != "AGPL-3.0" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_with_dependency() -> TestResult {
    use crate::npkg::types::Dependency;

    let dep = Dependency::runtime("libfoo", VersionRequirement::Any);
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .dependency(dep)
        .build()
        .unwrap();

    if manifest.package.dependencies.len() != 1 {
        return TestResult::Fail;
    }
    if manifest.package.dependencies[0].name != "libfoo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_with_install_script() -> TestResult {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .install_script("mkdir -p /opt/test")
        .build()
        .unwrap();

    if manifest.package.install_script != Some(alloc::string::String::from("mkdir -p /opt/test")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_with_remove_script() -> TestResult {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .remove_script("rm -rf /opt/test")
        .build()
        .unwrap();

    if manifest.package.remove_script != Some(alloc::string::String::from("rm -rf /opt/test")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_builder_default() -> TestResult {
    let builder: ManifestBuilder = Default::default();
    let result = builder.name("test").version(PackageVersion::new(1, 0, 0)).build();
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_simple() -> TestResult {
    let data = b"name = \"testpkg\"\nversion = \"1.0.0\"\ndescription = \"Test\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.meta.name != "testpkg" {
        return TestResult::Fail;
    }
    if manifest.package.meta.version.major != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_quotes() -> TestResult {
    let data = b"name = \"my-package\"\nversion = \"2.0.0\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.meta.name != "my-package" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_missing_name() -> TestResult {
    let data = b"version = \"1.0.0\"\n";
    let result = parse_manifest(data);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_missing_version() -> TestResult {
    let data = b"name = \"test\"\n";
    let result = parse_manifest(data);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_comments() -> TestResult {
    let data = b"# This is a comment\nname = \"test\"\n# Another comment\nversion = \"1.0.0\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_empty_lines() -> TestResult {
    let data = b"\n\nname = \"test\"\n\nversion = \"1.0.0\"\n\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_architecture() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\narchitecture = \"x86_64\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.meta.architecture != Architecture::X86_64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_arch_shorthand() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\narch = \"aarch64\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.meta.architecture != Architecture::Aarch64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_kind() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\nkind = \"library\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.meta.kind != PackageKind::Library {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_type_shorthand() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\ntype = \"driver\"\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.meta.kind != PackageKind::Driver {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_dependencies() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\nlibfoo\nlibbar>=1.0.0\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.dependencies.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_optional_dependency() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\noptional: extra-feature: enables feature X\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.dependencies.len() != 1 {
        return TestResult::Fail;
    }
    if manifest.package.dependencies[0].kind != DependencyKind::Optional {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_conflict() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\nconflict: other-pkg\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.dependencies[0].kind != DependencyKind::Conflict {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_files() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/usr/bin/test exec\n/etc/test.conf config\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.files.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_file_executable() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/usr/bin/test exec\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.files[0].permissions.mode != 0o755 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_file_config() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/etc/test.conf config\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if !manifest.package.files[0].is_config {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_file_directory() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/opt/test/ dir\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if !manifest.package.files[0].is_directory {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_install_section() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[install]\nmkdir -p /opt/test\ntouch /opt/test/.installed\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.install_script.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_with_remove_section() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[remove]\nrm -rf /opt/test\n";
    let result = parse_manifest(data);
    if result.is_err() {
        return TestResult::Fail;
    }
    let manifest = result.unwrap();
    if manifest.package.remove_script.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_parse_manifest_invalid_utf8() -> TestResult {
    let data = &[0xff, 0xfe, 0x00];
    let result = parse_manifest(data);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serialize_manifest_simple() -> TestResult {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .description("A test")
        .build()
        .unwrap();

    let bytes = serialize_manifest(&manifest);
    let text = core::str::from_utf8(&bytes).unwrap();
    if !text.contains("name = \"test\"") {
        return TestResult::Fail;
    }
    if !text.contains("version = \"1.0.0\"") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_serialize_then_parse() -> TestResult {
    let original = ManifestBuilder::new()
        .name("roundtrip")
        .version(PackageVersion::new(2, 3, 4))
        .description("Roundtrip test")
        .license("MIT")
        .build()
        .unwrap();

    let bytes = serialize_manifest(&original);
    let parsed = parse_manifest(&bytes).unwrap();

    if original.package.meta.name != parsed.package.meta.name {
        return TestResult::Fail;
    }
    if original.package.meta.version != parsed.package.meta.version {
        return TestResult::Fail;
    }
    if original.package.meta.license != parsed.package.meta.license {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_raw_bytes() -> TestResult {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n";
    let manifest = parse_manifest(data).unwrap();
    if manifest.raw_bytes() != data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_manifest_new() -> TestResult {
    use crate::npkg::types::{Package, PackageMeta};
    use alloc::vec::Vec;

    let meta = PackageMeta {
        name: alloc::string::String::from("test"),
        version: PackageVersion::new(1, 0, 0),
        description: alloc::string::String::new(),
        long_description: None,
        homepage: None,
        license: alloc::string::String::from("AGPL-3.0"),
        maintainer: None,
        architecture: Architecture::Any,
        kind: PackageKind::Binary,
        size_installed: 0,
        size_download: 0,
        checksum_blake3: [0u8; 32],
        signature: None,
    };

    let package = Package {
        meta,
        dependencies: Vec::new(),
        files: Vec::new(),
        install_script: None,
        remove_script: None,
    };

    let manifest = Manifest::new(package);
    if manifest.package.meta.name != "test" {
        return TestResult::Fail;
    }
    if !manifest.raw_bytes().is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
