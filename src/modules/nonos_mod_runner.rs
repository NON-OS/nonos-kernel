//! NØNOS Module Runner 

use crate::modules::nonos_module_loader::{start_module, stop_module, get_module_info, NonosModuleState};
use crate::modules::nonos_manifest::ModuleManifest;
use crate::modules::nonos_sandbox::{setup_sandbox, destroy_sandbox, SandboxConfig};
use crate::process::capabilities::Capability;
use crate::memory::secure_erase;
use crate::security::audit::{audit_event, AuditEvent};
use core::time::Duration;

/// Launches a module with enforced sandbox, attestation, and privacy.

pub fn run_module(module_id: u64, manifest: &ModuleManifest, sandbox_cfg: &SandboxConfig) -> Result<bool, &'static str> {
    // Enforce runtime attestation
    if !manifest.verify_attestation() {
        audit_event(AuditEvent::AttestationFailure { module: manifest.name.clone() });
        return Err("Runtime attestation failed");
    }

    // Enforce capability boundary (RAM-only, never persisted)
    if !manifest.capabilities.iter().all(|cap| cap.is_allowed()) {
        audit_event(AuditEvent::CapabilityViolation { module: manifest.name.clone() });
        return Err("Capability boundary violation");
    }

    // Set up isolated sandbox context (RAM only)
    setup_sandbox(module_id, sandbox_cfg)?;

    // Start module runtime, record audit
    start_module(module_id)?;
    audit_event(AuditEvent::ModuleStarted { module: manifest.name.clone() });

    // Check running state
    let info = get_module_info(module_id)?;
    let running = info.state == NonosModuleState::Running;

    // Audit running state
    if running {
        audit_event(AuditEvent::ModuleRunning { module: manifest.name.clone() });
    } else {
        audit_event(AuditEvent::ModuleStartFailure { module: manifest.name.clone() });
    }
    Ok(running)
}

/// Securely stop a module
pub fn stop_and_erase_module(module_id: u64, sandbox_cfg: &SandboxConfig, manifest: &ModuleManifest) -> Result<(), &'static str> {
    stop_module(module_id)?;
    destroy_sandbox(module_id, sandbox_cfg)?;

    // Securely erase all runtime process memory 
    if let Ok(info) = get_module_info(module_id) {
        secure_erase_module_runtime(info.memory_base, info.memory_size);
    }
    audit_event(AuditEvent::ModuleStopped { module: manifest.name.clone() });

    // Securely erase manifest and any runtime metadata
    let mut manifest = manifest.clone();
    manifest.secure_erase();

    Ok(())
}

pub fn stop_module_runtime(module_id: u64) -> Result<(), &'static str> {
    stop_module(module_id)
}

pub fn start_module_runtime(module_id: u64) -> Result<(), &'static str> {
    start_module(module_id)
}

/// Securely wipes the memory region (RAM-only, zero-state).
fn secure_erase_module_runtime(memory_base: Option<u64>, memory_size: usize) {
    if let Some(base) = memory_base {
        unsafe {
            secure_erase(core::slice::from_raw_parts_mut(base as *mut u8, memory_size));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::nonos_manifest::{ModuleManifest, PrivacyPolicy};
    use crate::modules::nonos_sandbox::SandboxConfig;

    /// Dummy audit hook for test
    pub fn audit_event(event: crate::security::audit::AuditEvent) {}

    #[test]
    fn test_run_module_attestation_fail() {
        let manifest = ModuleManifest::new(
            "Test".into(), "1.0".into(), "Anon".into(), "Desc".into(),
            vec![], PrivacyPolicy::ZeroStateOnly, vec![], b"modcode"
        );
        let sandbox_cfg = SandboxConfig::default();
        // Dummy module id
        assert!(run_module(42, &manifest, &sandbox_cfg).is_err());
    }

    #[test]
    fn test_stop_and_erase_module_secure() {
        let manifest = ModuleManifest::new(
            "EraseMe".into(), "1.0".into(), "Anon".into(), "Desc".into(),
            vec![], PrivacyPolicy::ZeroStateOnly, vec![], b"modcode"
        );
        let sandbox_cfg = SandboxConfig::default();
        // Dummy module id
        assert!(stop_and_erase_module(42, &sandbox_cfg, &manifest).is_ok());
    }
}
