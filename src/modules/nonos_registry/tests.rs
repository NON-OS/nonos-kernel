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
use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};

fn create_test_manifest(name: &str) -> ModuleManifest {
    ModuleManifest::new(
        name.into(),
        "1.0".into(),
        "Author".into(),
        "Description".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"module code",
    )
}

#[test]
fn test_registry_entry_creation() {
    let manifest = create_test_manifest("TestEntry");
    let entry = RegistryEntry::new(manifest.clone(), true);

    assert_eq!(entry.hash, manifest.hash);
    assert!(entry.attested);
    assert_eq!(entry.registered_at, 0);
}

#[test]
fn test_registry_entry_with_timestamp() {
    let manifest = create_test_manifest("Timestamped");
    let entry = RegistryEntry::new(manifest, true).with_timestamp(12345);

    assert_eq!(entry.registered_at, 12345);
}

#[test]
fn test_register_and_list() {
    let manifest = create_test_manifest("TestMod");
    assert!(register_module(&manifest).is_ok());
    assert!(list_registered_modules().contains(&"TestMod".into()));
    assert!(unregister_module("TestMod").is_ok());
}

#[test]
fn test_register_invalid_privacy_policy() {
    let manifest = ModuleManifest::new(
        "InvalidPolicy".into(),
        "1.0".into(),
        "Author".into(),
        "Desc".into(),
        vec![],
        PrivacyPolicy::None, // Invalid for registry
        vec![],
        b"code",
    );

    let result = register_module(&manifest);
    assert_eq!(result, Err(RegistryError::InvalidPrivacyPolicy));
}

#[test]
fn test_register_duplicate() {
    let manifest = create_test_manifest("Duplicate");
    register_module(&manifest).unwrap();

    let result = register_module(&manifest);
    assert_eq!(result, Err(RegistryError::AlreadyExists));

    unregister_module("Duplicate").unwrap();
}

#[test]
fn test_unregister_not_found() {
    let result = unregister_module("NonExistent");
    assert_eq!(result, Err(RegistryError::NotFound));
}

#[test]
fn test_is_module_registered() {
    let manifest = create_test_manifest("CheckRegistered");
    assert!(!is_module_registered("CheckRegistered"));

    register_module(&manifest).unwrap();
    assert!(is_module_registered("CheckRegistered"));

    unregister_module("CheckRegistered").unwrap();
    assert!(!is_module_registered("CheckRegistered"));
}

#[test]
fn test_get_registry_entry() {
    let manifest = create_test_manifest("GetEntry");
    register_module(&manifest).unwrap();

    let entry = get_registry_entry("GetEntry");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().manifest.name, "GetEntry");

    unregister_module("GetEntry").unwrap();
}

#[test]
fn test_secure_erase_registry_entry() {
    let manifest = create_test_manifest("EraseMe");
    register_module(&manifest).unwrap();

    assert!(secure_erase_registry_entry("EraseMe").is_ok());

    let entry = get_registry_entry("EraseMe");
    assert!(entry.is_some());
    let entry = entry.unwrap();
    assert_eq!(entry.manifest.name, "");
    assert_eq!(entry.hash, [0u8; 32]);
    assert!(!entry.attested);

    unregister_module("EraseMe").unwrap();
}

#[test]
fn test_secure_unregister_module() {
    let manifest = create_test_manifest("SecureUnreg");
    register_module(&manifest).unwrap();

    assert!(secure_unregister_module("SecureUnreg").is_ok());
    assert!(!is_module_registered("SecureUnreg"));
}

#[test]
fn test_error_messages() {
    assert_eq!(
        RegistryError::InvalidPrivacyPolicy.as_str(),
        "Registry only accepts ZeroState/Ephemeral modules"
    );
    assert_eq!(
        RegistryError::AttestationFailed.as_str(),
        "Registry attestation failed"
    );
    assert_eq!(
        RegistryError::NotFound.as_str(),
        "Module not found in registry"
    );
}
