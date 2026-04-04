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

#[test]
fn test_service_bind_and_resolve() {
    service::bind("test_service", "test_capsule");
    let resolved = service::resolve("test_service");
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap(), "test_capsule");
    service::unbind("test_service");
}

#[test]
fn test_service_unbind() {
    service::bind("unbind_test", "capsule_to_unbind");
    service::unbind("unbind_test");
    let resolved = service::resolve("unbind_test");
    assert!(resolved.is_none());
}

#[test]
fn test_service_resolve_nonexistent() {
    let resolved = service::resolve("nonexistent_service_xyz");
    assert!(resolved.is_none());
}

#[test]
fn test_service_bind_overwrites() {
    service::bind("overwrite_test", "capsule_v1");
    service::bind("overwrite_test", "capsule_v2");
    let resolved = service::resolve("overwrite_test");
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap(), "capsule_v2");
    service::unbind("overwrite_test");
}

#[test]
fn test_service_multiple_bindings() {
    service::bind("service_a", "capsule_a");
    service::bind("service_b", "capsule_b");
    service::bind("service_c", "capsule_c");

    let a = service::resolve("service_a");
    let b = service::resolve("service_b");
    let c = service::resolve("service_c");

    assert!(a.is_some());
    assert!(b.is_some());
    assert!(c.is_some());
    assert_eq!(a.unwrap(), "capsule_a");
    assert_eq!(b.unwrap(), "capsule_b");
    assert_eq!(c.unwrap(), "capsule_c");

    service::unbind("service_a");
    service::unbind("service_b");
    service::unbind("service_c");
}

#[test]
fn test_service_unbind_nonexistent() {
    service::unbind("never_existed_service");
}

#[test]
fn test_service_resolve_after_unbind() {
    service::bind("resolve_after_unbind", "some_capsule");
    let before = service::resolve("resolve_after_unbind");
    assert!(before.is_some());

    service::unbind("resolve_after_unbind");
    let after = service::resolve("resolve_after_unbind");
    assert!(after.is_none());
}

#[test]
fn test_service_bind_same_capsule_multiple_services() {
    service::bind("service_1", "shared_capsule");
    service::bind("service_2", "shared_capsule");
    service::bind("service_3", "shared_capsule");

    let s1 = service::resolve("service_1");
    let s2 = service::resolve("service_2");
    let s3 = service::resolve("service_3");

    assert_eq!(s1.unwrap(), "shared_capsule");
    assert_eq!(s2.unwrap(), "shared_capsule");
    assert_eq!(s3.unwrap(), "shared_capsule");

    service::unbind("service_1");
    service::unbind("service_2");
    service::unbind("service_3");
}

#[test]
fn test_service_bind_empty_string() {
    service::bind("", "empty_service_capsule");
    let resolved = service::resolve("");
    assert!(resolved.is_some());
    service::unbind("");
}

#[test]
fn test_service_bind_long_names() {
    let long_service = "a_very_long_service_name_that_goes_on_and_on";
    let long_capsule = "a_very_long_capsule_name_that_also_goes_on";
    service::bind(long_service, long_capsule);
    let resolved = service::resolve(long_service);
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap(), long_capsule);
    service::unbind(long_service);
}

#[test]
fn test_service_resolve_returns_string() {
    service::bind("string_test", "capsule_string");
    let resolved = service::resolve("string_test");
    assert!(resolved.is_some());
    let s: alloc::string::String = resolved.unwrap();
    assert!(!s.is_empty());
    service::unbind("string_test");
}

#[test]
fn test_service_bind_special_characters() {
    service::bind("service-with-dashes", "capsule_dashes");
    service::bind("service.with.dots", "capsule_dots");
    service::bind("service_with_underscores", "capsule_underscores");

    assert!(service::resolve("service-with-dashes").is_some());
    assert!(service::resolve("service.with.dots").is_some());
    assert!(service::resolve("service_with_underscores").is_some());

    service::unbind("service-with-dashes");
    service::unbind("service.with.dots");
    service::unbind("service_with_underscores");
}

#[test]
fn test_service_unbind_partial_does_not_affect_others() {
    service::bind("partial_a", "cap_a");
    service::bind("partial_b", "cap_b");

    service::unbind("partial_a");

    assert!(service::resolve("partial_a").is_none());
    assert!(service::resolve("partial_b").is_some());

    service::unbind("partial_b");
}

#[test]
fn test_service_rebind_after_unbind() {
    service::bind("rebind_test", "original_capsule");
    service::unbind("rebind_test");
    service::bind("rebind_test", "new_capsule");

    let resolved = service::resolve("rebind_test");
    assert!(resolved.is_some());
    assert_eq!(resolved.unwrap(), "new_capsule");

    service::unbind("rebind_test");
}

#[test]
fn test_service_resolve_case_sensitive() {
    service::bind("CaseSensitive", "capsule_case");

    let upper = service::resolve("CaseSensitive");
    let lower = service::resolve("casesensitive");

    assert!(upper.is_some());
    assert!(lower.is_none());

    service::unbind("CaseSensitive");
}

#[test]
fn test_service_numeric_names() {
    service::bind("123", "capsule_123");
    service::bind("456", "capsule_456");

    assert!(service::resolve("123").is_some());
    assert!(service::resolve("456").is_some());

    service::unbind("123");
    service::unbind("456");
}
