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

use super::*;

#[test]
fn test_module_type_default() {
    assert_eq!(ModuleType::default(), ModuleType::User);
}

#[test]
fn test_privacy_policy_ram_only() {
    assert!(PrivacyPolicy::ZeroStateOnly.is_ram_only());
    assert!(PrivacyPolicy::Ephemeral.is_ram_only());
    assert!(!PrivacyPolicy::EncryptedPersistent.is_ram_only());
}

#[test]
fn test_manifest_new() {
    let code = b"test code";
    let manifest = ModuleManifest::new("test", code);
    assert_eq!(manifest.name, "test");
    assert!(manifest.hash != [0u8; 32]);
}

#[test]
fn test_manifest_verify_hash() {
    let code = b"test code";
    let manifest = ModuleManifest::new("test", code);
    assert!(manifest.verify_hash(code));
    assert!(!manifest.verify_hash(b"different"));
}

#[test]
fn test_manifest_builder() {
    let manifest = ManifestBuilder::new("test", b"code")
        .version("2.0.0")
        .author("NONOS")
        .module_type(ModuleType::System)
        .privacy_policy(PrivacyPolicy::ZeroStateOnly)
        .capability(1)
        .capability(2)
        .build()
        .unwrap();

    assert_eq!(manifest.version, "2.0.0");
    assert_eq!(manifest.author, "NONOS");
    assert_eq!(manifest.module_type, ModuleType::System);
    assert!(manifest.has_capability(1));
    assert!(manifest.has_capability(2));
}

#[test]
fn test_manifest_builder_empty_name() {
    let result = ManifestBuilder::new("", b"code").build();
    assert!(matches!(result, Err(ManifestError::EmptyName)));
}

#[test]
fn test_manifest_secure_erase() {
    let mut manifest = ModuleManifest::new("test", b"code");
    manifest.author = alloc::string::String::from("author");
    manifest.secure_erase();

    assert!(manifest.name.is_empty());
    assert!(manifest.author.is_empty());
    assert_eq!(manifest.hash, [0u8; 32]);
}

#[test]
fn test_memory_requirements_default() {
    let mem = MemoryRequirements::default();
    assert_eq!(mem.min_heap, DEFAULT_MIN_HEAP);
    assert_eq!(mem.max_heap, DEFAULT_MAX_HEAP);
    assert!(!mem.needs_dma);
}
