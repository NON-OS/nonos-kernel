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
use crate::modules::nonos_sandbox::SandboxConfig;
use crate::process::capabilities::{Capability, CapabilitySet};

#[test]
fn test_fault_policy_default() {
    let policy = FaultPolicy::default();
    assert_eq!(policy, FaultPolicy::Terminate);
}

#[test]
fn test_runner_context_creation() {
    let caps = CapabilitySet::new();
    let ctx = RunnerContext::new(42, caps);

    assert_eq!(ctx.module_id, 42);
    assert!(!ctx.is_running);
    assert!(ctx.memory_base.is_none());
    assert_eq!(ctx.memory_size, 0);
}

#[test]
fn test_runner_context_builder() {
    let mut caps = CapabilitySet::new();
    caps.insert(Capability::Read.bit());

    let ctx = RunnerContext::new(123, caps)
        .with_fault_policy(FaultPolicy::Restart)
        .with_memory(0x1000, 4096);

    assert_eq!(ctx.module_id, 123);
    assert_eq!(ctx.fault_policy, FaultPolicy::Restart);
    assert_eq!(ctx.memory_base, Some(0x1000));
    assert_eq!(ctx.memory_size, 4096);
}

#[test]
fn test_run_module_attestation_fail() {
    let manifest = ModuleManifest::new(
        "TestModule".into(),
        "1.0".into(),
        "Anonymous".into(),
        "Test module".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![], // Empty attestation chain will fail verification
        b"test module code",
    );
    let sandbox_cfg = SandboxConfig::default();

    let result = run_module(42, &manifest, &sandbox_cfg);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), RunnerError::AttestationFailed);
}

#[test]
fn test_run_module_capability_violation() {
    let manifest = ModuleManifest::new(
        "AdminModule".into(),
        "1.0".into(),
        "Anonymous".into(),
        "Module requesting admin".into(),
        vec![Capability::Admin], // Requests admin
        PrivacyPolicy::ZeroStateOnly,
        vec![], // Will fail attestation first, but capability check would also fail
        b"admin module code",
    );

    let sandbox_cfg = SandboxConfig::new(4096).with_capability(Capability::Read);

    let result = run_module(43, &manifest, &sandbox_cfg);
    assert!(result.is_err());
}

#[test]
fn test_stop_and_erase_module() {
    let mut manifest = ModuleManifest::new(
        "EraseMe".into(),
        "1.0".into(),
        "Anonymous".into(),
        "Module to erase".into(),
        vec![],
        PrivacyPolicy::ZeroStateOnly,
        vec![],
        b"module code",
    );
    let sandbox_cfg = SandboxConfig::default();

    let _ = stop_and_erase_module(42, &sandbox_cfg, &mut manifest);

    assert_eq!(manifest.name, "");
    assert_eq!(manifest.version, "");
    assert_eq!(manifest.hash, [0u8; 32]);
}

#[test]
fn test_error_messages() {
    assert_eq!(RunnerError::AttestationFailed.as_str(), "Runtime attestation failed");
    assert_eq!(RunnerError::CapabilityViolation.as_str(), "Capability boundary violation");
    assert_eq!(RunnerError::SandboxSetupFailed.as_str(), "Failed to set up sandbox");
    assert_eq!(RunnerError::StartFailed.as_str(), "Failed to start module");
    assert_eq!(RunnerError::StopFailed.as_str(), "Failed to stop module");
}
