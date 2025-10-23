//! NØNOS Secure Module Registry

use alloc::{string::String, vec::Vec, collections::BTreeMap};
use spin::Mutex;
use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};
use crate::crypto::blake3::blake3_hash;
use crate::security::trusted_keys::{TrustedKey, get_trusted_keys};

/// RAM-only registry of loaded modules. Privacy: never persists to disk.
static MODULE_REGISTRY: Mutex<BTreeMap<String, RegistryEntry>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub manifest: ModuleManifest,
    pub hash: [u8; 32],
    pub attested: bool,
}

pub fn register_module(manifest: &ModuleManifest) -> Result<(), &'static str> {
    // Enforce privacy: only ZeroState or Ephemeral modules allowed
    match manifest.privacy_policy {
        PrivacyPolicy::ZeroStateOnly | PrivacyPolicy::Ephemeral => {},
        _ => return Err("Registry only accepts ZeroState/Ephemeral modules"),
    }
    // Attestation required
    let attested = manifest.verify_attestation();
    if !attested {
        return Err("Registry attestation failed");
    }
    let hash = manifest.hash;
    MODULE_REGISTRY.lock().insert(manifest.name.clone(), RegistryEntry {
        manifest: manifest.clone(),
        hash,
        attested,
    });
    Ok(())
}

pub fn unregister_module(module_name: &str) -> Result<(), &'static str> {
    let mut reg = MODULE_REGISTRY.lock();
    if reg.remove(module_name).is_some() {
        Ok(())
    } else {
        Err("Module not found in registry")
    }
}

/// List registered modules (RAM-only, never written to disk).
pub fn list_registered_modules() -> Vec<String> {
    MODULE_REGISTRY.lock().keys().cloned().collect()
}

/// Securely erase registry entry for privacy
pub fn secure_erase_registry_entry(module_name: &str) -> Result<(), &'static str> {
    let mut reg = MODULE_REGISTRY.lock();
    if let Some(entry) = reg.get_mut(module_name) {
        entry.manifest.secure_erase();
        entry.hash = [0u8; 32];
        Ok(())
    } else {
        Err("No such module in registry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};

    #[test]
    fn test_register_and_list() {
        let manifest = ModuleManifest::new(
            "TestMod".into(), "1.0".into(), "Author".into(), "Desc".into(),
            vec![], PrivacyPolicy::ZeroStateOnly, vec![], b"modcode"
        );
        assert!(register_module(&manifest).is_ok());
        assert!(list_registered_modules().contains(&"TestMod".into()));
        assert!(unregister_module("TestMod").is_ok());
    }

    #[test]
    fn test_secure_erase_registry_entry() {
        let manifest = ModuleManifest::new(
            "EraseMe".into(), "1.0".into(), "Author".into(), "Desc".into(),
            vec![], PrivacyPolicy::ZeroStateOnly, vec![], b"modcode"
        );
        register_module(&manifest).unwrap();
        assert!(secure_erase_registry_entry("EraseMe").is_ok());
        unregister_module("EraseMe").unwrap();
    }
}
