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
fn test_sandbox_config_default() {
    let cfg = SandboxConfig::default();
    assert_eq!(cfg.memory_limit, 4096);
    assert!(cfg.allowed_capabilities.is_empty());
    assert!(!cfg.audit);
    assert!(!cfg.quantum_isolation);
}

#[test]
fn test_sandbox_config_builder() {
    let cfg = SandboxConfig::new(8192)
        .with_capability(Capability::Read)
        .with_capability(Capability::Write)
        .with_audit()
        .with_quantum_isolation();

    assert_eq!(cfg.memory_limit, 8192);
    assert!(cfg.allowed_capabilities.can_read());
    assert!(cfg.allowed_capabilities.can_write());
    assert!(cfg.audit);
    assert!(cfg.quantum_isolation);
}

#[test]
fn test_setup_and_destroy_sandbox_basic() {
    let cfg = SandboxConfig::new(4096);
    let module_id = 12345;

    assert!(setup_sandbox(module_id, &cfg).is_ok());
    assert!(is_sandbox_active(module_id));
    assert!(destroy_sandbox(module_id, &cfg).is_ok());
    assert!(!is_sandbox_active(module_id));
}

#[test]
fn test_setup_sandbox_zero_memory_fails() {
    let cfg = SandboxConfig::new(0);
    let result = setup_sandbox(99999, &cfg);
    assert_eq!(result, Err(SandboxError::ZeroMemoryLimit));
}

#[test]
fn test_setup_sandbox_duplicate_fails() {
    let cfg = SandboxConfig::new(4096);
    let module_id = 11111;

    assert!(setup_sandbox(module_id, &cfg).is_ok());
    let result = setup_sandbox(module_id, &cfg);
    assert_eq!(result, Err(SandboxError::AlreadyExists));

    destroy_sandbox(module_id, &cfg).ok();
}

#[test]
fn test_destroy_nonexistent_fails() {
    let cfg = SandboxConfig::default();
    let result = destroy_sandbox(999999, &cfg);
    assert_eq!(result, Err(SandboxError::NotFound));
}

#[test]
fn test_sandbox_capability_checking() {
    let cfg = SandboxConfig::new(4096)
        .with_capability(Capability::Read)
        .with_capability(Capability::Write);
    let module_id = 22222;

    setup_sandbox(module_id, &cfg).unwrap();

    assert!(sandbox_has_capability(module_id, Capability::Read));
    assert!(sandbox_has_capability(module_id, Capability::Write));
    assert!(!sandbox_has_capability(module_id, Capability::Admin));

    assert!(sandbox_has_all_capabilities(
        module_id,
        &[Capability::Read, Capability::Write]
    ));
    assert!(!sandbox_has_all_capabilities(
        module_id,
        &[Capability::Read, Capability::Admin]
    ));

    destroy_sandbox(module_id, &cfg).unwrap();
}

#[test]
fn test_list_active_sandboxes() {
    let cfg = SandboxConfig::new(4096);
    let module_id = 33333;

    setup_sandbox(module_id, &cfg).unwrap();
    let active = list_active_sandboxes();
    assert!(active.contains(&module_id));
    destroy_sandbox(module_id, &cfg).unwrap();
}

#[test]
fn test_get_sandbox_capabilities() {
    let cfg = SandboxConfig::new(4096)
        .with_capability(Capability::Read);
    let module_id = 44444;

    setup_sandbox(module_id, &cfg).unwrap();

    let caps = get_sandbox_capabilities(module_id);
    assert!(caps.is_some());
    assert!(caps.unwrap().can_read());

    destroy_sandbox(module_id, &cfg).unwrap();

    assert!(get_sandbox_capabilities(module_id).is_none());
}

#[test]
fn test_validate_capabilities() {
    use crate::process::capabilities::CapabilitySet;

    let mut allowed = CapabilitySet::new();
    allowed.insert(Capability::Read.bit());
    allowed.insert(Capability::Write.bit());

    assert!(validate_capabilities(&[Capability::Read], &allowed).is_ok());
    assert!(validate_capabilities(&[Capability::Read, Capability::Write], &allowed).is_ok());

    assert_eq!(
        validate_capabilities(&[Capability::Admin], &allowed),
        Err(SandboxError::CapabilityViolation)
    );
}

#[test]
fn test_setup_with_quantum_isolation() {
    let cfg = SandboxConfig::new(4096).with_quantum_isolation();
    let module_id = 55555;

    assert!(setup_sandbox(module_id, &cfg).is_ok());
    assert!(is_sandbox_active(module_id));
    assert!(destroy_sandbox(module_id, &cfg).is_ok());
}
