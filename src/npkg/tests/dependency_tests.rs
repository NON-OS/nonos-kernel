use crate::npkg::*;
use crate::npkg::types::{Dependency, DependencyKind, VersionRequirement, PackageVersion};

#[test]
fn test_dependency_runtime() {
    let dep = Dependency::runtime("libfoo", VersionRequirement::Any);
    assert_eq!(dep.name, "libfoo");
    assert_eq!(dep.kind, DependencyKind::Runtime);
    assert_eq!(dep.version, VersionRequirement::Any);
    assert!(dep.reason.is_none());
}

#[test]
fn test_dependency_runtime_with_version() {
    let req = VersionRequirement::GreaterOrEqual(PackageVersion::new(1, 0, 0));
    let dep = Dependency::runtime("libbar", req.clone());
    assert_eq!(dep.name, "libbar");
    assert_eq!(dep.kind, DependencyKind::Runtime);
    assert_eq!(dep.version, req);
}

#[test]
fn test_dependency_optional() {
    let dep = Dependency::optional("optional-feature", "enables feature X");
    assert_eq!(dep.name, "optional-feature");
    assert_eq!(dep.kind, DependencyKind::Optional);
    assert_eq!(dep.version, VersionRequirement::Any);
    assert_eq!(dep.reason, Some(alloc::string::String::from("enables feature X")));
}

#[test]
fn test_dependency_conflict() {
    let dep = Dependency::conflict("conflicting-pkg");
    assert_eq!(dep.name, "conflicting-pkg");
    assert_eq!(dep.kind, DependencyKind::Conflict);
    assert_eq!(dep.version, VersionRequirement::Any);
    assert!(dep.reason.is_none());
}

#[test]
fn test_dependency_parse_simple() {
    let dep = Dependency::parse("libfoo");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    assert_eq!(dep.name, "libfoo");
    assert_eq!(dep.kind, DependencyKind::Runtime);
    assert_eq!(dep.version, VersionRequirement::Any);
}

#[test]
fn test_dependency_parse_with_version_greater_equal() {
    let dep = Dependency::parse("libfoo>=1.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    assert_eq!(dep.name, "libfoo");
    if let VersionRequirement::GreaterOrEqual(v) = dep.version {
        assert_eq!(v.major, 1);
    } else {
        panic!("expected GreaterOrEqual");
    }
}

#[test]
fn test_dependency_parse_with_version_greater() {
    let dep = Dependency::parse("libbar>2.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    assert_eq!(dep.name, "libbar");
    if let VersionRequirement::GreaterThan(v) = dep.version {
        assert_eq!(v.major, 2);
    } else {
        panic!("expected GreaterThan");
    }
}

#[test]
fn test_dependency_parse_with_version_less_equal() {
    let dep = Dependency::parse("libqux<=3.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    if let VersionRequirement::LessOrEqual(v) = dep.version {
        assert_eq!(v.major, 3);
    } else {
        panic!("expected LessOrEqual");
    }
}

#[test]
fn test_dependency_parse_with_version_less() {
    let dep = Dependency::parse("pkg<4.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    if let VersionRequirement::LessThan(v) = dep.version {
        assert_eq!(v.major, 4);
    } else {
        panic!("expected LessThan");
    }
}

#[test]
fn test_dependency_parse_with_version_exact() {
    let dep = Dependency::parse("pkg=5.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    if let VersionRequirement::Exact(v) = dep.version {
        assert_eq!(v.major, 5);
    } else {
        panic!("expected Exact");
    }
}

#[test]
fn test_dependency_parse_with_version_compatible() {
    let dep = Dependency::parse("pkg^1.2.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    if let VersionRequirement::Compatible(v) = dep.version {
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
    } else {
        panic!("expected Compatible");
    }
}

#[test]
fn test_dependency_parse_empty() {
    let dep = Dependency::parse("");
    assert!(dep.is_none());
}

#[test]
fn test_dependency_parse_whitespace_only() {
    let dep = Dependency::parse("   ");
    assert!(dep.is_none());
}

#[test]
fn test_dependency_parse_with_whitespace() {
    let dep = Dependency::parse("  libfoo  ");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    assert_eq!(dep.name, "libfoo");
}

#[test]
fn test_dependency_clone() {
    let dep = Dependency::runtime("test", VersionRequirement::Any);
    let cloned = dep.clone();
    assert_eq!(dep.name, cloned.name);
    assert_eq!(dep.kind, cloned.kind);
}

#[test]
fn test_dependency_kind_variants() {
    let kinds = [
        DependencyKind::Runtime,
        DependencyKind::Build,
        DependencyKind::Optional,
        DependencyKind::Conflict,
        DependencyKind::Replace,
        DependencyKind::Provide,
    ];
    assert_eq!(kinds.len(), 6);
}

#[test]
fn test_dependency_parse_name_with_hyphen() {
    let dep = Dependency::parse("my-cool-lib>=1.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    assert_eq!(dep.name, "my-cool-lib");
}

#[test]
fn test_dependency_parse_name_with_underscore() {
    let dep = Dependency::parse("my_lib>=2.0.0");
    assert!(dep.is_some());
    let dep = dep.unwrap();
    assert_eq!(dep.name, "my_lib");
}

#[test]
fn test_version_requirement_equality() {
    let req1 = VersionRequirement::Any;
    let req2 = VersionRequirement::Any;
    assert_eq!(req1, req2);
}

#[test]
fn test_version_requirement_exact_equality() {
    let v = PackageVersion::new(1, 0, 0);
    let req1 = VersionRequirement::Exact(v.clone());
    let req2 = VersionRequirement::Exact(v);
    assert_eq!(req1, req2);
}

#[test]
fn test_version_requirement_clone() {
    let req = VersionRequirement::GreaterThan(PackageVersion::new(1, 0, 0));
    let cloned = req.clone();
    assert_eq!(req, cloned);
}
