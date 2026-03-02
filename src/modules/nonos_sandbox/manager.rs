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


use alloc::vec::Vec;
use spin::Mutex;
use crate::process::capabilities::{Capability, CapabilitySet};
use crate::memory::{
    memory::zero_memory,
    allocator::{allocate_pages, free_pages},
    VirtAddr,
};
use crate::security::audit::{audit_event, AuditSeverity};
use super::types::{SandboxConfig, SandboxState};
use super::error::{SandboxError, SandboxResult};
use super::crypto::{generate_quantum_keys, secure_erase_quantum_keys};

static SANDBOXES: Mutex<Vec<SandboxState>> = Mutex::new(Vec::new());

static MAX_SANDBOX_CAPABILITIES: Mutex<Option<CapabilitySet>> = Mutex::new(None);

pub fn init_sandbox_boundary(max_caps: CapabilitySet) {
    *MAX_SANDBOX_CAPABILITIES.lock() = Some(max_caps);
}

fn validate_capability_request(requested: &CapabilitySet) -> SandboxResult<()> {
    if let Some(ref max_caps) = *MAX_SANDBOX_CAPABILITIES.lock() {
        if !max_caps.is_superset_of(requested) {
            return Err(SandboxError::CapabilityViolation);
        }
    }
    Ok(())
}

pub fn validate_capabilities(
    required: &[Capability],
    allowed: &CapabilitySet,
) -> SandboxResult<()> {
    for cap in required {
        if allowed.bits() & (1u64 << cap.bit()) == 0 {
            return Err(SandboxError::CapabilityViolation);
        }
    }
    Ok(())
}

pub fn setup_sandbox(module_id: u64, config: &SandboxConfig) -> SandboxResult<()> {
    if config.memory_limit == 0 {
        return Err(SandboxError::ZeroMemoryLimit);
    }

    {
        let sandboxes = SANDBOXES.lock();
        if sandboxes.iter().any(|s| s.module_id == module_id) {
            return Err(SandboxError::AlreadyExists);
        }
    }

    validate_capability_request(&config.allowed_capabilities)?;

    let num_pages = (config.memory_limit + 4095) / 4096;
    let base_addr = allocate_pages(num_pages)
        .map_err(|_| SandboxError::MemoryAllocationFailed)?;

    let quantum_keys = if config.quantum_isolation {
        Some(generate_quantum_keys()?)
    } else {
        None
    };

    let state = SandboxState {
        module_id,
        base_addr: base_addr.as_u64() as usize,
        size: config.memory_limit,
        capabilities: config.allowed_capabilities,
        quantum_keys,
    };

    SANDBOXES.lock().push(state);

    if config.audit {
        audit_event(
            "sandbox",
            AuditSeverity::Info,
            format!("Sandbox created for module {}", module_id),
            None,
            None,
            None,
        );
    }

    Ok(())
}

pub fn destroy_sandbox(module_id: u64, config: &SandboxConfig) -> SandboxResult<()> {
    let mut sandboxes = SANDBOXES.lock();

    let idx = sandboxes
        .iter()
        .position(|s| s.module_id == module_id)
        .ok_or(SandboxError::NotFound)?;

    let mut state = sandboxes.remove(idx);

    zero_memory(VirtAddr::new(state.base_addr as u64), state.size)
        .map_err(|_| SandboxError::SecureEraseFailed)?;

    free_pages(VirtAddr::new(state.base_addr as u64), (state.size + 4095) / 4096)
        .map_err(|_| SandboxError::MemoryFreeFailed)?;

    if let Some(ref mut keys) = state.quantum_keys {
        secure_erase_quantum_keys(keys);
    }

    if config.audit {
        audit_event(
            "sandbox",
            AuditSeverity::Info,
            format!("Sandbox destroyed for module {}", module_id),
            None,
            None,
            None,
        );
    }

    Ok(())
}

pub fn is_sandbox_active(module_id: u64) -> bool {
    SANDBOXES.lock().iter().any(|s| s.module_id == module_id)
}

pub fn list_active_sandboxes() -> Vec<u64> {
    SANDBOXES.lock().iter().map(|s| s.module_id).collect()
}

pub fn sandbox_has_capability(module_id: u64, cap: Capability) -> bool {
    SANDBOXES
        .lock()
        .iter()
        .find(|s| s.module_id == module_id)
        .map(|s| s.has_capability(cap))
        .unwrap_or(false)
}

pub fn sandbox_has_all_capabilities(module_id: u64, required: &[Capability]) -> bool {
    SANDBOXES
        .lock()
        .iter()
        .find(|s| s.module_id == module_id)
        .map(|s| s.has_all_capabilities(required))
        .unwrap_or(false)
}

pub fn get_sandbox_capabilities(module_id: u64) -> Option<CapabilitySet> {
    SANDBOXES
        .lock()
        .iter()
        .find(|s| s.module_id == module_id)
        .map(|s| s.capabilities)
}
