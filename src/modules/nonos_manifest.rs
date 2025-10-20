//! NØNOS Module Manifest 

use alloc::{string::String, vec::Vec};
use crate::crypto::blake3::blake3_hash;
use crate::security::trusted_keys::{get_trusted_keys, TrustedKey};
use crate::process::capabilities::Capability;

#[derive(Debug, Clone)]
pub struct ModuleManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub capabilities: Vec<Capability>,
    pub privacy_policy: PrivacyPolicy,
    pub attestation_chain: Vec<TrustedKey>,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyPolicy {
    ZeroStateOnly,          // No persistent storage, RAM-only, erased on unload
    Ephemeral,              // Temporary data allowed (RAM), wiped on session end
    EncryptedPersistent,    // Data at rest is encrypted with ephemeral keys
    None,                   // No privacy guarantees (not recommended)
}

impl ModuleManifest {
    /// Create manifest 
    pub fn new(
        name: String,
        version: String,
        author: String,
        description: String,
        capabilities: Vec<Capability>,
        privacy_policy: PrivacyPolicy,
        attestation_chain: Vec<TrustedKey>,
        module_code: &[u8],
    ) -> Self {
        let hash = blake3_hash(module_code);
        Self {
            name,
            version,
            author,
            description,
            capabilities,
            privacy_policy,
            attestation_chain,
            hash,
        }
    }

    /// Verify manifest
    pub fn verify_attestation(&self) -> bool {
        for key in &self.attestation_chain {
            if !get_trusted_keys().contains(key) {
                return false;
            }
        }
        true
    }

    /// Erase manifest from RAM.
    pub fn secure_erase(&mut self) {
        self.name.clear();
        self.version.clear();
        self.author.clear();
        self.description.clear();
        self.capabilities.clear();
        self.attestation_chain.clear();
        self.hash = [0u8; 32];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_manifest_creation_and_erase() {
        let manifest = ModuleManifest::new(
            "Test".to_string(),
            "1.0".to_string(),
            "Author".to_string(),
            "Desc".to_string(),
            vec![],
            PrivacyPolicy::ZeroStateOnly,
            vec![],
            b"modcode"
        );
        assert!(manifest.hash != [0u8; 32]);
        let mut manifest2 = manifest.clone();
        manifest2.secure_erase();
        assert_eq!(manifest2.name, "");
        assert_eq!(manifest2.hash, [0u8; 32]);
    }
}
