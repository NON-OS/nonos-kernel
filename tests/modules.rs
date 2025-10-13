//! Tests for NØNOS modules subsystem

extern crate alloc;

use nonos_kernel::modules::{
    nonos_auth::*,
    nonos_manifest::*,
    nonos_loader::*,
    nonos_mod_runner::*,
    nonos_registry::*,
    nonos_sandbox::*,
    nonos_module_loader::*,
    LoadedModule,
};

#[test]
fn test_module_manifest_and_auth_integration() {
    let code = b"test module code";
    let manifest = ModuleManifest::new(
        "integrationmod".to_string(),
        "0.1.0".to_string(),
        "anon".to_string(),
        "integration test".to_string(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        code,
    );

    // Simulate auth
    let sig = [0u8; 64];
    let pk = [0u8; 32];
    let res = authenticate_module(code, &sig, &pk, None, None, None);
    assert!(!res.verified, "Dummy signature should fail");

    // Manifest attestation (no chain)
    assert!(manifest.verify_attestation(), "Empty attestation chain should pass (test stub)");
}

#[test]
fn test_sandbox_and_registry_lifecycle() {
    let module_id = 10001;
    let cfg = SandboxConfig {
        memory_limit: 4096,
        allowed_capabilities: vec![],
        audit: true,
        quantum_isolation: true,
    };
    assert!(setup_sandbox(module_id, &cfg).is_ok());
    assert!(is_sandbox_active(module_id));

    // Registry interaction
    let code = b"test module code";
    let manifest = ModuleManifest::new(
        "regmod".to_string(),
        "1.0".to_string(),
        "anon".to_string(),
        "registry test".to_string(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        code,
    );
    assert!(register_module(&manifest).is_ok());
    assert!(list_registered_modules().contains(&"regmod".to_string()));

    // Remove from registry and destroy sandbox
    assert!(unregister_module("regmod").is_ok());
    assert!(destroy_sandbox(module_id, &cfg).is_ok());
    assert!(!is_sandbox_active(module_id));
}

#[test]
fn test_loader_and_runner_integration() {
    let code = b"modcode";
    let manifest = ModuleManifest::new(
        "loadrun".to_string(),
        "1.0".to_string(),
        "anon".to_string(),
        "test loader/runner".to_string(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        code,
    );
    let req = LoaderRequest {
        manifest: manifest.clone(),
        code: code.to_vec(),
        ed25519_signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        pqc_signature: None,
        pqc_pubkey: None,
    };
    let policy = LoaderPolicy {
        privacy_enforced: false,
        required_privacy: PrivacyPolicy::ZeroStateOnly,
        enforce_attestation: false,
        enforce_capabilities: false,
        sandbox_config: None,
    };

    // Should fail to load due to dummy signature
    assert!(load(req, &policy).is_err());

    // Simulate runner 
    let sandbox_cfg = SandboxConfig::default();
    assert!(run_module(123, &manifest, &sandbox_cfg).is_err());
}

#[test]
fn test_module_loader_registry_lifecycle() {
    let loaded = LoadedModule {
        name: "testmod".to_string(),
        base_address: 0x1000,
        size: 4096,
        hash: [1u8; 32],
        verified: true,
        entry_point: Some(0x1000),
        msg_queue_offset: 4096,
    };
    assert!(register_loaded_module(loaded.clone()).is_ok());
    assert!(is_module_active("testmod"));
    assert_eq!(get_loaded_modules().len(), 1);
    assert!(unload_module("testmod").is_ok());
    assert!(!is_module_active("testmod"));
}
