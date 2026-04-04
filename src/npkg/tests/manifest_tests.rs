use crate::npkg::*;
use crate::npkg::types::{PackageVersion, Architecture, PackageKind, DependencyKind, VersionRequirement};

#[test]
fn test_manifest_builder_new() {
    let builder = ManifestBuilder::new();
    let result = builder.name("test").version(PackageVersion::new(1, 0, 0)).build();
    assert!(result.is_ok());
}

#[test]
fn test_manifest_builder_missing_name() {
    let builder = ManifestBuilder::new();
    let result = builder.version(PackageVersion::new(1, 0, 0)).build();
    assert!(result.is_err());
}

#[test]
fn test_manifest_builder_missing_version() {
    let builder = ManifestBuilder::new();
    let result = builder.name("test").build();
    assert!(result.is_err());
}

#[test]
fn test_manifest_builder_full() {
    let manifest = ManifestBuilder::new()
        .name("testpkg")
        .version(PackageVersion::new(1, 2, 3))
        .description("A test package")
        .license("MIT")
        .architecture(Architecture::X86_64)
        .kind(PackageKind::Binary)
        .build()
        .unwrap();

    assert_eq!(manifest.package.meta.name, "testpkg");
    assert_eq!(manifest.package.meta.version.major, 1);
    assert_eq!(manifest.package.meta.description, "A test package");
    assert_eq!(manifest.package.meta.license, "MIT");
    assert_eq!(manifest.package.meta.architecture, Architecture::X86_64);
    assert_eq!(manifest.package.meta.kind, PackageKind::Binary);
}

#[test]
fn test_manifest_builder_default_license() {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .build()
        .unwrap();

    assert_eq!(manifest.package.meta.license, "AGPL-3.0");
}

#[test]
fn test_manifest_builder_with_dependency() {
    use crate::npkg::types::Dependency;

    let dep = Dependency::runtime("libfoo", VersionRequirement::Any);
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .dependency(dep)
        .build()
        .unwrap();

    assert_eq!(manifest.package.dependencies.len(), 1);
    assert_eq!(manifest.package.dependencies[0].name, "libfoo");
}

#[test]
fn test_manifest_builder_with_install_script() {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .install_script("mkdir -p /opt/test")
        .build()
        .unwrap();

    assert_eq!(manifest.package.install_script, Some(alloc::string::String::from("mkdir -p /opt/test")));
}

#[test]
fn test_manifest_builder_with_remove_script() {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .remove_script("rm -rf /opt/test")
        .build()
        .unwrap();

    assert_eq!(manifest.package.remove_script, Some(alloc::string::String::from("rm -rf /opt/test")));
}

#[test]
fn test_manifest_builder_default() {
    let builder: ManifestBuilder = Default::default();
    let result = builder.name("test").version(PackageVersion::new(1, 0, 0)).build();
    assert!(result.is_ok());
}

#[test]
fn test_parse_manifest_simple() {
    let data = b"name = \"testpkg\"\nversion = \"1.0.0\"\ndescription = \"Test\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.meta.name, "testpkg");
    assert_eq!(manifest.package.meta.version.major, 1);
}

#[test]
fn test_parse_manifest_with_quotes() {
    let data = b"name = \"my-package\"\nversion = \"2.0.0\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.meta.name, "my-package");
}

#[test]
fn test_parse_manifest_missing_name() {
    let data = b"version = \"1.0.0\"\n";
    let result = parse_manifest(data);
    assert!(result.is_err());
}

#[test]
fn test_parse_manifest_missing_version() {
    let data = b"name = \"test\"\n";
    let result = parse_manifest(data);
    assert!(result.is_err());
}

#[test]
fn test_parse_manifest_with_comments() {
    let data = b"# This is a comment\nname = \"test\"\n# Another comment\nversion = \"1.0.0\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
}

#[test]
fn test_parse_manifest_with_empty_lines() {
    let data = b"\n\nname = \"test\"\n\nversion = \"1.0.0\"\n\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
}

#[test]
fn test_parse_manifest_with_architecture() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\narchitecture = \"x86_64\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.meta.architecture, Architecture::X86_64);
}

#[test]
fn test_parse_manifest_with_arch_shorthand() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\narch = \"aarch64\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.meta.architecture, Architecture::Aarch64);
}

#[test]
fn test_parse_manifest_with_kind() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\nkind = \"library\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.meta.kind, PackageKind::Library);
}

#[test]
fn test_parse_manifest_with_type_shorthand() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\ntype = \"driver\"\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.meta.kind, PackageKind::Driver);
}

#[test]
fn test_parse_manifest_with_dependencies() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\nlibfoo\nlibbar>=1.0.0\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.dependencies.len(), 2);
}

#[test]
fn test_parse_manifest_with_optional_dependency() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\noptional: extra-feature: enables feature X\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.dependencies.len(), 1);
    assert_eq!(manifest.package.dependencies[0].kind, DependencyKind::Optional);
}

#[test]
fn test_parse_manifest_with_conflict() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[dependencies]\nconflict: other-pkg\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.dependencies[0].kind, DependencyKind::Conflict);
}

#[test]
fn test_parse_manifest_with_files() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/usr/bin/test exec\n/etc/test.conf config\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.files.len(), 2);
}

#[test]
fn test_parse_manifest_file_executable() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/usr/bin/test exec\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert_eq!(manifest.package.files[0].permissions.mode, 0o755);
}

#[test]
fn test_parse_manifest_file_config() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/etc/test.conf config\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert!(manifest.package.files[0].is_config);
}

#[test]
fn test_parse_manifest_file_directory() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[files]\n/opt/test/ dir\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert!(manifest.package.files[0].is_directory);
}

#[test]
fn test_parse_manifest_with_install_section() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[install]\nmkdir -p /opt/test\ntouch /opt/test/.installed\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert!(manifest.package.install_script.is_some());
}

#[test]
fn test_parse_manifest_with_remove_section() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n\n[remove]\nrm -rf /opt/test\n";
    let result = parse_manifest(data);
    assert!(result.is_ok());
    let manifest = result.unwrap();
    assert!(manifest.package.remove_script.is_some());
}

#[test]
fn test_parse_manifest_invalid_utf8() {
    let data = &[0xff, 0xfe, 0x00];
    let result = parse_manifest(data);
    assert!(result.is_err());
}

#[test]
fn test_serialize_manifest_simple() {
    let manifest = ManifestBuilder::new()
        .name("test")
        .version(PackageVersion::new(1, 0, 0))
        .description("A test")
        .build()
        .unwrap();

    let bytes = serialize_manifest(&manifest);
    let text = core::str::from_utf8(&bytes).unwrap();
    assert!(text.contains("name = \"test\""));
    assert!(text.contains("version = \"1.0.0\""));
}

#[test]
fn test_serialize_then_parse() {
    let original = ManifestBuilder::new()
        .name("roundtrip")
        .version(PackageVersion::new(2, 3, 4))
        .description("Roundtrip test")
        .license("MIT")
        .build()
        .unwrap();

    let bytes = serialize_manifest(&original);
    let parsed = parse_manifest(&bytes).unwrap();

    assert_eq!(original.package.meta.name, parsed.package.meta.name);
    assert_eq!(original.package.meta.version, parsed.package.meta.version);
    assert_eq!(original.package.meta.license, parsed.package.meta.license);
}

#[test]
fn test_manifest_raw_bytes() {
    let data = b"name = \"test\"\nversion = \"1.0.0\"\n";
    let manifest = parse_manifest(data).unwrap();
    assert_eq!(manifest.raw_bytes(), data);
}

#[test]
fn test_manifest_new() {
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
    assert_eq!(manifest.package.meta.name, "test");
    assert!(manifest.raw_bytes().is_empty());
}
