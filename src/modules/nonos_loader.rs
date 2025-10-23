//! NØNOS High-Level Module Loader Orchestrator 

use alloc::{string::String, vec::Vec};
use crate::modules::nonos_module_loader::{load_module, unload_module, NonosModuleType, get_module_info};
use crate::modules::nonos_manifest::ModuleManifest;
use crate::modules::nonos_auth::{authenticate_module, AuthContext};
use crate::modules::nonos_sandbox::SandboxConfig;
use crate::modules::nonos_registry::register_module;
use crate::modules::nonos_mod_runner::{run_module, stop_module_runtime, start_module_runtime};

/// Orchestrator config: privacy, capability, attestation controls
#[derive(Debug, Clone)]
pub struct LoaderPolicy {
    pub privacy_enforced: bool,
    pub required_privacy: crate::modules::nonos_manifest::PrivacyPolicy,
    pub enforce_attestation: bool,
    pub enforce_capabilities: bool,
    pub sandbox_config: Option<SandboxConfig>,
}

/// Top-level module load request
#[derive(Debug, Clone)]
pub struct LoaderRequest {
    pub manifest: ModuleManifest,
    pub code: Vec<u8>,
    pub ed25519_signature: [u8; 64],
    pub ed25519_pubkey: [u8; 32],
    pub pqc_signature: Option<Vec<u8>>,
    pub pqc_pubkey: Option<Vec<u8>>,
}

/// Load a module, enforcing all privacy/security policies and registering for runtime
pub fn load(request: LoaderRequest, policy: &LoaderPolicy) -> Result<u64, &'static str> {
    // Privacy policy check
    if policy.privacy_enforced && request.manifest.privacy_policy != policy.required_privacy {
        return Err("Privacy policy mismatch");
    }

    // Attestation/capability checks
    if policy.enforce_attestation && !request.manifest.verify_attestation() {
        return Err("Attestation chain not trusted");
    }
    if policy.enforce_capabilities {
        // At least one required capability must be present
        if request.manifest.capabilities.is_empty() {
            return Err("No capabilities present");
        }
    }

    // Authenticate module code 
    let auth = authenticate_module(
        &request.code,
        &request.ed25519_signature,
        &request.ed25519_pubkey,
        request.pqc_signature.as_deref(),
        request.pqc_pubkey.as_deref(),
        None, // attestation handled above
    );

    if !auth.verified && !auth.pqc_verified {
        return Err("Module authentication failed");
    }

    // Register manifest in system registry (RAM-only)
    register_module(&request.manifest)?;

    // Load module code into RAM, cryptographically verified
    let module_id = load_module(
        &request.manifest.name,
        NonosModuleType::Application,
        request.code,
        &request.ed25519_signature,
    )?;

    // Optional launch in sandbox
    if let Some(ref sandbox_cfg) = policy.sandbox_config {
        crate::modules::nonos_sandbox::setup_sandbox(module_id, sandbox_cfg)?;
    }

    // Start runtime (RAM-only, zero-state)
    start_module_runtime(module_id)?;

    Ok(module_id)
}

/// Unload a module and securely erase all metadata and code
pub fn unload(module_id: u64) -> Result<(), &'static str> {
    stop_module_runtime(module_id)?;
    unload_module(module_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};

    #[test]
    fn test_policy_privacy_enforced() {
        let manifest = ModuleManifest::new(
            "Test".into(), "1.0".into(), "Anon".into(), "Desc".into(),
            vec![], PrivacyPolicy::ZeroStateOnly, vec![], b"modcode"
        );
        let req = LoaderRequest {
            manifest: manifest,
            code: vec![1, 2, 3, 4, 5, 6, 7, 8],
            ed25519_signature: [0u8; 64],
            ed25519_pubkey: [0u8; 32],
            pqc_signature: None,
            pqc_pubkey: None,
        };
        let policy = LoaderPolicy {
            privacy_enforced: true,
            required_privacy: PrivacyPolicy::Ephemeral,
            enforce_attestation: false,
            enforce_capabilities: false,
            sandbox_config: None,
        };
        assert!(load(req, &policy).is_err());
    }
}
