use crate::npkg::types::{PackageVersion, VersionRequirement};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_version_new() -> TestResult {
    let v = PackageVersion::new(1, 2, 3);
    if v.major != 1 {
        return TestResult::Fail;
    }
    if v.minor != 2 {
        return TestResult::Fail;
    }
    if v.patch != 3 {
        return TestResult::Fail;
    }
    if v.pre_release.is_some() {
        return TestResult::Fail;
    }
    if v.build.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_simple() -> TestResult {
    let v = PackageVersion::parse("1.2.3");
    if v.is_none() {
        return TestResult::Fail;
    }
    let v = v.unwrap();
    if v.major != 1 {
        return TestResult::Fail;
    }
    if v.minor != 2 {
        return TestResult::Fail;
    }
    if v.patch != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_two_parts() -> TestResult {
    let v = PackageVersion::parse("1.2");
    if v.is_none() {
        return TestResult::Fail;
    }
    let v = v.unwrap();
    if v.major != 1 {
        return TestResult::Fail;
    }
    if v.minor != 2 {
        return TestResult::Fail;
    }
    if v.patch != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_with_prerelease() -> TestResult {
    let v = PackageVersion::parse("1.0.0-alpha");
    if v.is_none() {
        return TestResult::Fail;
    }
    let v = v.unwrap();
    if v.major != 1 {
        return TestResult::Fail;
    }
    if v.minor != 0 {
        return TestResult::Fail;
    }
    if v.patch != 0 {
        return TestResult::Fail;
    }
    if v.pre_release != Some(alloc::string::String::from("alpha")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_with_build() -> TestResult {
    let v = PackageVersion::parse("1.0.0+build123");
    if v.is_none() {
        return TestResult::Fail;
    }
    let v = v.unwrap();
    if v.major != 1 {
        return TestResult::Fail;
    }
    if v.minor != 0 {
        return TestResult::Fail;
    }
    if v.patch != 0 {
        return TestResult::Fail;
    }
    if v.build != Some(alloc::string::String::from("build123")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_with_prerelease_and_build() -> TestResult {
    let v = PackageVersion::parse("1.0.0-beta.1+build456");
    if v.is_none() {
        return TestResult::Fail;
    }
    let v = v.unwrap();
    if v.pre_release != Some(alloc::string::String::from("beta.1")) {
        return TestResult::Fail;
    }
    if v.build != Some(alloc::string::String::from("build456")) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_with_whitespace() -> TestResult {
    let v = PackageVersion::parse("  1.2.3  ");
    if v.is_none() {
        return TestResult::Fail;
    }
    let v = v.unwrap();
    if v.major != 1 {
        return TestResult::Fail;
    }
    if v.minor != 2 {
        return TestResult::Fail;
    }
    if v.patch != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_invalid_single_part() -> TestResult {
    let v = PackageVersion::parse("1");
    if v.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_invalid_four_parts() -> TestResult {
    let v = PackageVersion::parse("1.2.3.4");
    if v.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_parse_invalid_non_numeric() -> TestResult {
    let v = PackageVersion::parse("a.b.c");
    if v.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_to_string_simple() -> TestResult {
    let v = PackageVersion::new(1, 2, 3);
    if v.to_string() != "1.2.3" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_to_string_with_prerelease() -> TestResult {
    let mut v = PackageVersion::new(1, 0, 0);
    v.pre_release = Some(alloc::string::String::from("rc1"));
    if v.to_string() != "1.0.0-rc1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_to_string_with_build() -> TestResult {
    let mut v = PackageVersion::new(1, 0, 0);
    v.build = Some(alloc::string::String::from("20260101"));
    if v.to_string() != "1.0.0+20260101" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_to_string_with_both() -> TestResult {
    let mut v = PackageVersion::new(2, 0, 0);
    v.pre_release = Some(alloc::string::String::from("alpha"));
    v.build = Some(alloc::string::String::from("build1"));
    if v.to_string() != "2.0.0-alpha+build1" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_comparison_equal() -> TestResult {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = PackageVersion::new(1, 2, 3);
    if v1 != v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_comparison_major() -> TestResult {
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(2, 0, 0);
    if !(v1 < v2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_comparison_minor() -> TestResult {
    let v1 = PackageVersion::new(1, 1, 0);
    let v2 = PackageVersion::new(1, 2, 0);
    if !(v1 < v2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_comparison_patch() -> TestResult {
    let v1 = PackageVersion::new(1, 0, 1);
    let v2 = PackageVersion::new(1, 0, 2);
    if !(v1 < v2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_comparison_prerelease_less_than_release() -> TestResult {
    let mut v1 = PackageVersion::new(1, 0, 0);
    v1.pre_release = Some(alloc::string::String::from("alpha"));
    let v2 = PackageVersion::new(1, 0, 0);
    if !(v1 < v2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_comparison_prerelease_ordering() -> TestResult {
    let mut v1 = PackageVersion::new(1, 0, 0);
    v1.pre_release = Some(alloc::string::String::from("alpha"));
    let mut v2 = PackageVersion::new(1, 0, 0);
    v2.pre_release = Some(alloc::string::String::from("beta"));
    if !(v1 < v2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_any() -> TestResult {
    let req = VersionRequirement::parse("*");
    if req != Some(VersionRequirement::Any) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_empty() -> TestResult {
    let req = VersionRequirement::parse("");
    if req != Some(VersionRequirement::Any) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_exact() -> TestResult {
    let req = VersionRequirement::parse("=1.0.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::Exact(v)) = req {
        if v.major != 1 {
            return TestResult::Fail;
        }
        if v.minor != 0 {
            return TestResult::Fail;
        }
        if v.patch != 0 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_exact_implicit() -> TestResult {
    let req = VersionRequirement::parse("1.0.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::Exact(v)) = req {
        if v.major != 1 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_greater_than() -> TestResult {
    let req = VersionRequirement::parse(">1.0.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::GreaterThan(v)) = req {
        if v.major != 1 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_greater_or_equal() -> TestResult {
    let req = VersionRequirement::parse(">=2.0.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::GreaterOrEqual(v)) = req {
        if v.major != 2 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_less_than() -> TestResult {
    let req = VersionRequirement::parse("<3.0.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::LessThan(v)) = req {
        if v.major != 3 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_less_or_equal() -> TestResult {
    let req = VersionRequirement::parse("<=4.0.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::LessOrEqual(v)) = req {
        if v.major != 4 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_requirement_parse_compatible() -> TestResult {
    let req = VersionRequirement::parse("^1.2.0");
    if req.is_none() {
        return TestResult::Fail;
    }
    if let Some(VersionRequirement::Compatible(v)) = req {
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

pub(crate) fn test_version_satisfies_any() -> TestResult {
    let v = PackageVersion::new(5, 0, 0);
    if !v.satisfies(&VersionRequirement::Any) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_exact_true() -> TestResult {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::Exact(PackageVersion::new(1, 0, 0));
    if !v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_exact_false() -> TestResult {
    let v = PackageVersion::new(1, 0, 1);
    let req = VersionRequirement::Exact(PackageVersion::new(1, 0, 0));
    if v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_greater_than_true() -> TestResult {
    let v = PackageVersion::new(2, 0, 0);
    let req = VersionRequirement::GreaterThan(PackageVersion::new(1, 0, 0));
    if !v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_greater_than_false() -> TestResult {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::GreaterThan(PackageVersion::new(1, 0, 0));
    if v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_greater_or_equal_true() -> TestResult {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::GreaterOrEqual(PackageVersion::new(1, 0, 0));
    if !v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_less_than_true() -> TestResult {
    let v = PackageVersion::new(0, 9, 0);
    let req = VersionRequirement::LessThan(PackageVersion::new(1, 0, 0));
    if !v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_less_or_equal_true() -> TestResult {
    let v = PackageVersion::new(1, 0, 0);
    let req = VersionRequirement::LessOrEqual(PackageVersion::new(1, 0, 0));
    if !v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_compatible_same_major() -> TestResult {
    let v = PackageVersion::new(1, 5, 0);
    let req = VersionRequirement::Compatible(PackageVersion::new(1, 2, 0));
    if !v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_compatible_different_major() -> TestResult {
    let v = PackageVersion::new(2, 0, 0);
    let req = VersionRequirement::Compatible(PackageVersion::new(1, 2, 0));
    if v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_satisfies_compatible_lower_version() -> TestResult {
    let v = PackageVersion::new(1, 1, 0);
    let req = VersionRequirement::Compatible(PackageVersion::new(1, 2, 0));
    if v.satisfies(&req) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_equality() -> TestResult {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = PackageVersion::new(1, 2, 3);
    if v1 != v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_clone() -> TestResult {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = v1.clone();
    if v1 != v2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
