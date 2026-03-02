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
use crate::process::capabilities::Capability;

#[test]
fn test_privacy_policy_default() {
    let policy = PrivacyPolicy::default();
    assert_eq!(policy, PrivacyPolicy::ZeroStateOnly);
}

#[test]
fn test_auth_method_default() {
    let method = AuthMethod::default();
    assert_eq!(method, AuthMethod::Ed25519Signature);
}

#[test]
fn test_module_type_default() {
    let mtype = ModuleType::default();
    assert_eq!(mtype, ModuleType::User);
}

#[test]
fn test_memory_requirements_default() {
    let req = MemoryRequirements::default();
    assert_eq!(req.min_heap, 4096);
    assert_eq!(req.max_heap, 1024 * 1024);
    assert_eq!(req.stack_size, 8192);
    assert!(!req.needs_dma);
}

#[test]
fn test_memory_requirements_validation() {
    let valid = MemoryRequirements::new(4096, 8192, 1024);
    assert!(valid.validate());

    let invalid = MemoryRequirements::new(8192, 4096, 1024);
    assert!(!invalid.validate());

    let zero_stack = MemoryRequirements::new(4096, 8192, 0);
    assert!(!zero_stack.validate());
}

#[test]
fn test_memory_requirements_with_dma() {
    let req = MemoryRequirements::new(4096, 8192, 1024).with_dma();
    assert!(req.needs_dma);
}

#[test]
fn test_manifest_creation() {
    let manifest = ModuleManifest::new(
        "TestModule".into(),
        "1.0.0".into(),
        "Author".into(),
        "Description".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"module code bytes",
    );

    assert_eq!(manifest.name, "TestModule");
    assert_eq!(manifest.version, "1.0.0");
    assert_ne!(manifest.hash, [0u8; 32]);
}

#[test]
fn test_manifest_builder_pattern() {
    let manifest = ModuleManifest::new(
        "Test".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::Ephemeral,
        vec![],
        b"code",
    )
    .with_type(ModuleType::Driver)
    .with_auth_method(AuthMethod::VaultSignature)
    .with_memory_requirements(MemoryRequirements::new(1024, 2048, 512));

    assert_eq!(manifest.module_type, ModuleType::Driver);
    assert_eq!(manifest.auth_method, AuthMethod::VaultSignature);
    assert_eq!(manifest.memory_requirements.min_heap, 1024);
}

#[test]
fn test_manifest_secure_erase() {
    let mut manifest = ModuleManifest::new(
        "EraseMe".into(),
        "1.0".into(),
        "Author".into(),
        "Description".into(),
        vec![Capability::Read],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"module code",
    );

    assert!(!manifest.name.is_empty());
    assert_ne!(manifest.hash, [0u8; 32]);

    manifest.secure_erase();

    assert_eq!(manifest.name, "");
    assert_eq!(manifest.version, "");
    assert_eq!(manifest.author, "");
    assert_eq!(manifest.description, "");
    assert!(manifest.capabilities.is_empty());
    assert!(manifest.attestation_chain.is_empty());
    assert_eq!(manifest.hash, [0u8; 32]);
}

#[test]
fn test_manifest_validate() {
    let valid = ModuleManifest::new(
        "Valid".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"code",
    );
    assert!(valid.validate());

    let invalid_name = ModuleManifest::new(
        "".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"code",
    );
    assert!(!invalid_name.validate());

    let invalid_version = ModuleManifest::new(
        "Name".into(),
        "".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"code",
    );
    assert!(!invalid_version.validate());
}

#[test]
fn test_manifest_has_capability() {
    let manifest = ModuleManifest::new(
        "Test".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![Capability::Read, Capability::Write],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"code",
    );

    assert!(manifest.has_capability(&Capability::Read));
    assert!(manifest.has_capability(&Capability::Write));
    assert!(!manifest.has_capability(&Capability::Admin));
}
