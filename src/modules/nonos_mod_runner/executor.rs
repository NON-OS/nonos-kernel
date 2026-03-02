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


use alloc::format;
use crate::modules::nonos_module_loader::{start_module, stop_module, get_module_info, NonosModuleState};
use crate::modules::nonos_manifest::ModuleManifest;
use crate::modules::nonos_sandbox::{setup_sandbox, destroy_sandbox, SandboxConfig};
use crate::memory::memory::zero_memory;
use crate::security::audit::{audit_event, AuditSeverity};
use crate::process::capabilities::CapabilitySet;
use super::error::{RunnerError, RunnerResult};
use super::types::RunnerContext;

fn validate_module_capabilities(
    manifest: &ModuleManifest,
    allowed: &CapabilitySet,
) -> RunnerResult<()> {
    let mut required = CapabilitySet::new();
    for cap in &manifest.capabilities {
        required.insert(cap.bit());
    }

    if !allowed.is_superset_of(&required) {
        return Err(RunnerError::CapabilityViolation);
    }

    Ok(())
}

pub fn run_module(
    module_id: u64,
    manifest: &ModuleManifest,
    sandbox_cfg: &SandboxConfig,
) -> RunnerResult<RunnerContext> {
    if !manifest.verify_attestation() {
        audit_event(
            "modules",
            AuditSeverity::Critical,
            format!("Attestation failure for module: {}", manifest.name),
            None,
            Some(manifest.name.clone()),
            None,
        );
        return Err(RunnerError::AttestationFailed);
    }

    validate_module_capabilities(manifest, &sandbox_cfg.allowed_capabilities)?;

    audit_event(
        "modules",
        AuditSeverity::Info,
        format!("Capability validation passed for module: {}", manifest.name),
        None,
        Some(manifest.name.clone()),
        None,
    );

    setup_sandbox(module_id, sandbox_cfg).map_err(|e| {
        audit_event(
            "modules",
            AuditSeverity::Critical,
            format!("Sandbox setup failed for {}: {:?}", manifest.name, e),
            None,
            Some(manifest.name.clone()),
            None,
        );
        RunnerError::SandboxSetupFailed
    })?;

    start_module(module_id).map_err(|e| {
        audit_event(
            "modules",
            AuditSeverity::Critical,
            format!("Module start failed for {}: {:?}", manifest.name, e),
            None,
            Some(manifest.name.clone()),
            None,
        );
        RunnerError::StartFailed
    })?;

    audit_event(
        "modules",
        AuditSeverity::Info,
        format!("Module started: {}", manifest.name),
        None,
        Some(manifest.name.clone()),
        None,
    );

    let info = get_module_info(module_id).map_err(|_| RunnerError::ModuleInfoFailed)?;
    let is_running = info.state == NonosModuleState::Running;

    if is_running {
        audit_event(
            "modules",
            AuditSeverity::Info,
            format!("Module running: {}", manifest.name),
            None,
            Some(manifest.name.clone()),
            None,
        );
    } else {
        audit_event(
            "modules",
            AuditSeverity::Critical,
            format!("Module failed to reach running state: {}", manifest.name),
            None,
            Some(manifest.name.clone()),
            None,
        );
        return Err(RunnerError::InvalidState);
    }

    let context = RunnerContext::new(module_id, sandbox_cfg.allowed_capabilities)
        .with_memory(0, info.memory_size);

    Ok(RunnerContext {
        is_running: true,
        ..context
    })
}

pub fn stop_and_erase_module(
    module_id: u64,
    sandbox_cfg: &SandboxConfig,
    manifest: &mut ModuleManifest,
) -> RunnerResult<()> {
    stop_module(module_id).map_err(|_| RunnerError::StopFailed)?;

    destroy_sandbox(module_id, sandbox_cfg).map_err(|_| RunnerError::SandboxDestroyFailed)?;

    if let Ok(info) = get_module_info(module_id) {
        secure_erase_module_runtime(None, info.memory_size)?;
    }

    audit_event(
        "module_runner",
        AuditSeverity::Info,
        format!("Module stopped: {}", manifest.name),
        None,
        Some(manifest.name.clone()),
        None,
    );

    manifest.secure_erase();

    Ok(())
}

fn secure_erase_module_runtime(memory_base: Option<u64>, memory_size: usize) -> RunnerResult<()> {
    if let Some(base) = memory_base {
        zero_memory(x86_64::VirtAddr::new(base), memory_size)
            .map_err(|_| RunnerError::SecureEraseFailed)?;
    }
    Ok(())
}
