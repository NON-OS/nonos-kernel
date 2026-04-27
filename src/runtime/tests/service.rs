// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::runtime::*;
use crate::test::framework::TestResult;

pub(crate) fn test_service_bind_and_resolve() -> TestResult {
    service::bind("test_service", "test_capsule");
    let resolved = service::resolve("test_service");
    if !resolved.is_some() {
        return TestResult::Fail;
    }
    if resolved.unwrap() != "test_capsule" {
        return TestResult::Fail;
    }
    service::unbind("test_service");
    TestResult::Pass
}

pub(crate) fn test_service_unbind() -> TestResult {
    service::bind("unbind_test", "capsule_to_unbind");
    service::unbind("unbind_test");
    let resolved = service::resolve("unbind_test");
    if !resolved.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_resolve_nonexistent() -> TestResult {
    let resolved = service::resolve("nonexistent_service_xyz");
    if !resolved.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_bind_overwrites() -> TestResult {
    service::bind("overwrite_test", "capsule_v1");
    service::bind("overwrite_test", "capsule_v2");
    let resolved = service::resolve("overwrite_test");
    if !resolved.is_some() {
        return TestResult::Fail;
    }
    if resolved.unwrap() != "capsule_v2" {
        return TestResult::Fail;
    }
    service::unbind("overwrite_test");
    TestResult::Pass
}

pub(crate) fn test_service_multiple_bindings() -> TestResult {
    service::bind("service_a", "capsule_a");
    service::bind("service_b", "capsule_b");
    service::bind("service_c", "capsule_c");

    let a = service::resolve("service_a");
    let b = service::resolve("service_b");
    let c = service::resolve("service_c");

    if !a.is_some() {
        return TestResult::Fail;
    }
    if !b.is_some() {
        return TestResult::Fail;
    }
    if !c.is_some() {
        return TestResult::Fail;
    }
    if a.unwrap() != "capsule_a" {
        return TestResult::Fail;
    }
    if b.unwrap() != "capsule_b" {
        return TestResult::Fail;
    }
    if c.unwrap() != "capsule_c" {
        return TestResult::Fail;
    }

    service::unbind("service_a");
    service::unbind("service_b");
    service::unbind("service_c");
    TestResult::Pass
}

pub(crate) fn test_service_unbind_nonexistent() -> TestResult {
    service::unbind("never_existed_service");
    TestResult::Pass
}

pub(crate) fn test_service_resolve_after_unbind() -> TestResult {
    service::bind("resolve_after_unbind", "some_capsule");
    let before = service::resolve("resolve_after_unbind");
    if !before.is_some() {
        return TestResult::Fail;
    }

    service::unbind("resolve_after_unbind");
    let after = service::resolve("resolve_after_unbind");
    if !after.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_bind_same_capsule_multiple_services() -> TestResult {
    service::bind("service_1", "shared_capsule");
    service::bind("service_2", "shared_capsule");
    service::bind("service_3", "shared_capsule");

    let s1 = service::resolve("service_1");
    let s2 = service::resolve("service_2");
    let s3 = service::resolve("service_3");

    if s1.unwrap() != "shared_capsule" {
        return TestResult::Fail;
    }
    if s2.unwrap() != "shared_capsule" {
        return TestResult::Fail;
    }
    if s3.unwrap() != "shared_capsule" {
        return TestResult::Fail;
    }

    service::unbind("service_1");
    service::unbind("service_2");
    service::unbind("service_3");
    TestResult::Pass
}

pub(crate) fn test_service_bind_empty_string() -> TestResult {
    service::bind("", "empty_service_capsule");
    let resolved = service::resolve("");
    if !resolved.is_some() {
        return TestResult::Fail;
    }
    service::unbind("");
    TestResult::Pass
}

pub(crate) fn test_service_bind_long_names() -> TestResult {
    let long_service = "a_very_long_service_name_that_goes_on_and_on";
    let long_capsule = "a_very_long_capsule_name_that_also_goes_on";
    service::bind(long_service, long_capsule);
    let resolved = service::resolve(long_service);
    if !resolved.is_some() {
        return TestResult::Fail;
    }
    if resolved.unwrap() != long_capsule {
        return TestResult::Fail;
    }
    service::unbind(long_service);
    TestResult::Pass
}

pub(crate) fn test_service_resolve_returns_string() -> TestResult {
    service::bind("string_test", "capsule_string");
    let resolved = service::resolve("string_test");
    if !resolved.is_some() {
        return TestResult::Fail;
    }
    let s: alloc::string::String = resolved.unwrap();
    if s.is_empty() {
        return TestResult::Fail;
    }
    service::unbind("string_test");
    TestResult::Pass
}

pub(crate) fn test_service_bind_special_characters() -> TestResult {
    service::bind("service-with-dashes", "capsule_dashes");
    service::bind("service.with.dots", "capsule_dots");
    service::bind("service_with_underscores", "capsule_underscores");

    if !service::resolve("service-with-dashes").is_some() {
        return TestResult::Fail;
    }
    if !service::resolve("service.with.dots").is_some() {
        return TestResult::Fail;
    }
    if !service::resolve("service_with_underscores").is_some() {
        return TestResult::Fail;
    }

    service::unbind("service-with-dashes");
    service::unbind("service.with.dots");
    service::unbind("service_with_underscores");
    TestResult::Pass
}

pub(crate) fn test_service_unbind_partial_does_not_affect_others() -> TestResult {
    service::bind("partial_a", "cap_a");
    service::bind("partial_b", "cap_b");

    service::unbind("partial_a");

    if !service::resolve("partial_a").is_none() {
        return TestResult::Fail;
    }
    if !service::resolve("partial_b").is_some() {
        return TestResult::Fail;
    }

    service::unbind("partial_b");
    TestResult::Pass
}

pub(crate) fn test_service_rebind_after_unbind() -> TestResult {
    service::bind("rebind_test", "original_capsule");
    service::unbind("rebind_test");
    service::bind("rebind_test", "new_capsule");

    let resolved = service::resolve("rebind_test");
    if !resolved.is_some() {
        return TestResult::Fail;
    }
    if resolved.unwrap() != "new_capsule" {
        return TestResult::Fail;
    }

    service::unbind("rebind_test");
    TestResult::Pass
}

pub(crate) fn test_service_resolve_case_sensitive() -> TestResult {
    service::bind("CaseSensitive", "capsule_case");

    let upper = service::resolve("CaseSensitive");
    let lower = service::resolve("casesensitive");

    if !upper.is_some() {
        return TestResult::Fail;
    }
    if !lower.is_none() {
        return TestResult::Fail;
    }

    service::unbind("CaseSensitive");
    TestResult::Pass
}

pub(crate) fn test_service_numeric_names() -> TestResult {
    service::bind("123", "capsule_123");
    service::bind("456", "capsule_456");

    if !service::resolve("123").is_some() {
        return TestResult::Fail;
    }
    if !service::resolve("456").is_some() {
        return TestResult::Fail;
    }

    service::unbind("123");
    service::unbind("456");
    TestResult::Pass
}
