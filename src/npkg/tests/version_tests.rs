use crate::npkg::*;
use crate::npkg::types::{PackageVersion, VersionRequirement};

#[test]
fn test_version_new() {
    let v = PackageVersion::new(1, 2, 3);
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
    assert!(v.pre_release.is_none());
    assert!(v.build.is_none());
}

#[test]
fn test_version_parse_simple() {
    let v = PackageVersion::parse("1.2.3");
    assert!(v.is_some());
    let v = v.unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
}

#[test]
fn test_version_parse_two_parts() {
    let v = PackageVersion::parse("1.2");
    assert!(v.is_some());
    let v = v.unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 0);
}

#[test]
fn test_version_parse_with_prerelease() {
    let v = PackageVersion::parse("1.0.0-alpha");
    assert!(v.is_some());
    let v = v.unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.patch, 0);
    assert_eq!(v.pre_release, Some(alloc::string::String::from("alpha")));
}

#[test]
fn test_version_parse_with_build() {
    let v = PackageVersion::parse("1.0.0+build123");
    assert!(v.is_some());
    let v = v.unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 0);
    assert_eq!(v.patch, 0);
    assert_eq!(v.build, Some(alloc::string::String::from("build123")));
}

#[test]
fn test_version_parse_with_prerelease_and_build() {
    let v = PackageVersion::parse("1.0.0-beta.1+build456");
    assert!(v.is_some());
    let v = v.unwrap();
    assert_eq!(v.pre_release, Some(alloc::string::String::from("beta.1")));
    assert_eq!(v.build, Some(alloc::string::String::from("build456")));
}

#[test]
fn test_version_parse_with_whitespace() {
    let v = PackageVersion::parse("  1.2.3  ");
    assert!(v.is_some());
    let v = v.unwrap();
    assert_eq!(v.major, 1);
    assert_eq!(v.minor, 2);
    assert_eq!(v.patch, 3);
}

#[test]
fn test_version_parse_invalid_single_part() {
    let v = PackageVersion::parse("1");
    assert!(v.is_none());
}

#[test]
fn test_version_parse_invalid_four_parts() {
    let v = PackageVersion::parse("1.2.3.4");
    assert!(v.is_none());
}

#[test]
fn test_version_parse_invalid_non_numeric() {
    let v = PackageVersion::parse("a.b.c");
    assert!(v.is_none());
}

#[test]
fn test_version_to_string_simple() {
    let v = PackageVersion::new(1, 2, 3);
    assert_eq!(v.to_string(), "1.2.3");
}

#[test]
fn test_version_to_string_with_prerelease() {
    let mut v = PackageVersion::new(1, 0, 0);
    v.pre_release = Some(alloc::string::String::from("rc1"));
    assert_eq!(v.to_string(), "1.0.0-rc1");
}

#[test]
fn test_version_to_string_with_build() {
    let mut v = PackageVersion::new(1, 0, 0);
    v.build = Some(alloc::string::String::from("20260101"));
    assert_eq!(v.to_string(), "1.0.0+20260101");
}

#[test]
fn test_version_to_string_with_both() {
    let mut v = PackageVersion::new(2, 0, 0);
    v.pre_release = Some(alloc::string::String::from("alpha"));
    v.build = Some(alloc::string::String::from("build1"));
    assert_eq!(v.to_string(), "2.0.0-alpha+build1");
}

#[test]
fn test_version_comparison_equal() {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = PackageVersion::new(1, 2, 3);
    assert_eq!(v1, v2);
}

#[test]
fn test_version_comparison_major() {
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(2, 0, 0);
    assert!(v1 < v2);
}

#[test]
fn test_version_comparison_minor() {
    let v1 = PackageVersion::new(1, 1, 0);
    let v2 = PackageVersion::new(1, 2, 0);
    assert!(v1 < v2);
}

#[test]
fn test_version_comparison_patch() {
    let v1 = PackageVersion::new(1, 0, 1);
    let v2 = PackageVersion::new(1, 0, 2);
    assert!(v1 < v2);
}

#[test]
fn test_version_comparison_prerelease_less_than_release() {
    let mut v1 = PackageVersion::new(1, 0, 0);
    v1.pre_release = Some(alloc::string::String::from("alpha"));
    let v2 = PackageVersion::new(1, 0, 0);
    assert!(v1 < v2);
}

#[test]
fn test_version_comparison_prerelease_ordering() {
    let mut v1 = PackageVersion::new(1, 0, 0);
    v1.pre_release = Some(alloc::string::String::from("alpha"));
    let mut v2 = PackageVersion::new(1, 0, 0);
    v2.pre_release = Some(alloc::string::String::from("beta"));
    assert!(v1 < v2);
}

#[test]
fn test_version_requirement_parse_any() {
    let req = VersionRequirement::parse("*");
    assert_eq!(req, Some(VersionRequirement::Any));
}

#[test]
fn test_version_requirement_parse_empty() {
    let req = VersionRequirement::parse("");
    assert_eq!(req, Some(VersionRequirement::Any));
}

#[test]
fn test_version_requirement_parse_exact() {
    let req = VersionRequirement::parse("=1.0.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::Exact(v)) = req {
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    } else {
        panic!("expected Exact");
    }
}

#[test]
fn test_version_requirement_parse_exact_implicit() {
    let req = VersionRequirement::parse("1.0.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::Exact(v)) = req {
        assert_eq!(v.major, 1);
    } else {
        panic!("expected Exact");
    }
}

#[test]
fn test_version_requirement_parse_greater_than() {
    let req = VersionRequirement::parse(">1.0.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::GreaterThan(v)) = req {
        assert_eq!(v.major, 1);
    } else {
        panic!("expected GreaterThan");
    }
}

#[test]
fn test_version_requirement_parse_greater_or_equal() {
    let req = VersionRequirement::parse(">=2.0.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::GreaterOrEqual(v)) = req {
        assert_eq!(v.major, 2);
    } else {
        panic!("expected GreaterOrEqual");
    }
}

#[test]
fn test_version_requirement_parse_less_than() {
    let req = VersionRequirement::parse("<3.0.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::LessThan(v)) = req {
        assert_eq!(v.major, 3);
    } else {
        panic!("expected LessThan");
    }
}

#[test]
fn test_version_requirement_parse_less_or_equal() {
    let req = VersionRequirement::parse("<=4.0.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::LessOrEqual(v)) = req {
        assert_eq!(v.major, 4);
    } else {
        panic!("expected LessOrEqual");
    }
}

#[test]
fn test_version_requirement_parse_compatible() {
    let req = VersionRequirement::parse("^1.2.0");
    assert!(req.is_some());
    if let Some(VersionRequirement::Compatible(v)) = req {
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
    } else {
        panic!("expected Compatible");
    }
}

#[test]
fn test_version_satisfies_any() {
    let v = PackageVersion::new(5, 0, 0);
    assert!(v.satisfies(&VersionRequirement::Any));
}

#[test]
fn test_version_satisfies_exact_true() {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::Exact(PackageVersion::new(1, 0, 0));
    assert!(v.satisfies(&req));
}

#[test]
fn test_version_satisfies_exact_false() {
    let v = PackageVersion::new(1, 0, 1);
    let req = VersionRequirement::Exact(PackageVersion::new(1, 0, 0));
    assert!(!v.satisfies(&req));
}

#[test]
fn test_version_satisfies_greater_than_true() {
    let v = PackageVersion::new(2, 0, 0);
    let req = VersionRequirement::GreaterThan(PackageVersion::new(1, 0, 0));
    assert!(v.satisfies(&req));
}

#[test]
fn test_version_satisfies_greater_than_false() {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::GreaterThan(PackageVersion::new(1, 0, 0));
    assert!(!v.satisfies(&req));
}

#[test]
fn test_version_satisfies_greater_or_equal_true() {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::GreaterOrEqual(PackageVersion::new(1, 0, 0));
    assert!(v.satisfies(&req));
}

#[test]
fn test_version_satisfies_less_than_true() {
    let v = PackageVersion::new(0, 9, 0);
    let req = VersionRequirement::LessThan(PackageVersion::new(1, 0, 0));
    assert!(v.satisfies(&req));
}

#[test]
fn test_version_satisfies_less_or_equal_true() {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::LessOrEqual(PackageVersion::new(1, 0, 0));
    assert!(v.satisfies(&req));
}

#[test]
fn test_version_satisfies_compatible_same_major() {
    let v = PackageVersion::new(1, 5, 0);
    let req = VersionRequirement::Compatible(PackageVersion::new(1, 2, 0));
    assert!(v.satisfies(&req));
}

#[test]
fn test_version_satisfies_compatible_different_major() {
    let v = PackageVersion::new(2, 0, 0);
    let req = VersionRequirement::Compatible(PackageVersion::new(1, 2, 0));
    assert!(!v.satisfies(&req));
}

#[test]
fn test_version_satisfies_compatible_lower_version() {
    let v = PackageVersion::new(1, 1, 0);
    let req = VersionRequirement::Compatible(PackageVersion::new(1, 2, 0));
    assert!(!v.satisfies(&req));
}

#[test]
fn test_version_equality() {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = PackageVersion::new(1, 2, 3);
    assert_eq!(v1, v2);
}

#[test]
fn test_version_clone() {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = v1.clone();
    assert_eq!(v1, v2);
}
