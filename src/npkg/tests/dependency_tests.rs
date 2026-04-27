use crate::npkg::types::{Dependency, DependencyKind, PackageVersion, VersionRequirement};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_dependency_runtime() -> TestResult {
    let dep = Dependency::runtime("libfoo", VersionRequirement::Any);
    if dep.name != "libfoo" {
        return TestResult::Fail;
    }
    if dep.kind != DependencyKind::Runtime {
        return TestResult::Fail;
    }
    if dep.version != VersionRequirement::Any {
        return TestResult::Fail;
    }
    if dep.reason.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_runtime_with_version() -> TestResult {
    let req = VersionRequirement::GreaterOrEqual(PackageVersion::new(1, 0, 0));
    let dep = Dependency::runtime("libbar", req.clone());
    if dep.name != "libbar" {
        return TestResult::Fail;
    }
    if dep.kind != DependencyKind::Runtime {
        return TestResult::Fail;
    }
    if dep.version != req {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_optional() -> TestResult {
    let dep = Dependency::optional("optional-feature", "enables feature X");
    if dep.name != "optional-feature" {
        return TestResult::Fail;
    }
    if dep.kind != DependencyKind::Optional {
        return TestResult::Fail;
    }
    if dep.version != VersionRequirement::Any {
        return TestResult::Fail;
    }
    if dep.reason != Some(alloc::string::String::from("enables feature X")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_conflict() -> TestResult {
    let dep = Dependency::conflict("conflicting-pkg");
    if dep.name != "conflicting-pkg" {
        return TestResult::Fail;
    }
    if dep.kind != DependencyKind::Conflict {
        return TestResult::Fail;
    }
    if dep.version != VersionRequirement::Any {
        return TestResult::Fail;
    }
    if dep.reason.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_simple() -> TestResult {
    let dep = Dependency::parse("libfoo");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if dep.name != "libfoo" {
        return TestResult::Fail;
    }
    if dep.kind != DependencyKind::Runtime {
        return TestResult::Fail;
    }
    if dep.version != VersionRequirement::Any {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_version_greater_equal() -> TestResult {
    let dep = Dependency::parse("libfoo>=1.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if dep.name != "libfoo" {
        return TestResult::Fail;
    }
    if let VersionRequirement::GreaterOrEqual(v) = dep.version {
        if v.major != 1 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_version_greater() -> TestResult {
    let dep = Dependency::parse("libbar>2.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if dep.name != "libbar" {
        return TestResult::Fail;
    }
    if let VersionRequirement::GreaterThan(v) = dep.version {
        if v.major != 2 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_version_less_equal() -> TestResult {
    let dep = Dependency::parse("libqux<=3.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if let VersionRequirement::LessOrEqual(v) = dep.version {
        if v.major != 3 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_version_less() -> TestResult {
    let dep = Dependency::parse("pkg<4.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if let VersionRequirement::LessThan(v) = dep.version {
        if v.major != 4 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_version_exact() -> TestResult {
    let dep = Dependency::parse("pkg=5.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if let VersionRequirement::Exact(v) = dep.version {
        if v.major != 5 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_version_compatible() -> TestResult {
    let dep = Dependency::parse("pkg^1.2.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if let VersionRequirement::Compatible(v) = dep.version {
        if v.major != 1 {
            return TestResult::Fail;
        }
        if v.minor != 2 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_empty() -> TestResult {
    let dep = Dependency::parse("");
    if dep.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_whitespace_only() -> TestResult {
    let dep = Dependency::parse("   ");
    if dep.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_with_whitespace() -> TestResult {
    let dep = Dependency::parse("  libfoo  ");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if dep.name != "libfoo" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_clone() -> TestResult {
    let dep = Dependency::runtime("test", VersionRequirement::Any);
    let cloned = dep.clone();
    if dep.name != cloned.name {
        return TestResult::Fail;
    }
    if dep.kind != cloned.kind {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_kind_variants() -> TestResult {
    let kinds = [
        DependencyKind::Runtime,
        DependencyKind::Build,
        DependencyKind::Optional,
        DependencyKind::Conflict,
        DependencyKind::Replace,
        DependencyKind::Provide,
    ];
    if kinds.len() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_name_with_hyphen() -> TestResult {
    let dep = Dependency::parse("my-cool-lib>=1.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if dep.name != "my-cool-lib" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dependency_parse_name_with_underscore() -> TestResult {
    let dep = Dependency::parse("my_lib>=2.0.0");
    if dep.is_none() {
        return TestResult::Fail;
    }
    let dep = dep.unwrap();
    if dep.name != "my_lib" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_equality() -> TestResult {
    let req1 = VersionRequirement::Any;
    let req2 = VersionRequirement::Any;
    if req1 != req2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_exact_equality() -> TestResult {
    let v = PackageVersion::new(1, 0, 0);
    let req1 = VersionRequirement::Exact(v.clone());
    let req2 = VersionRequirement::Exact(v);
    if req1 != req2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_clone() -> TestResult {
    let req = VersionRequirement::GreaterThan(PackageVersion::new(1, 0, 0));
    let cloned = req.clone();
    if req != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}
