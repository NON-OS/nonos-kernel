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

#[test]
fn test_sandbox_config_default() {
    let config = SandboxConfig::default();
    assert_eq!(config.memory_limit, DEFAULT_MEMORY_LIMIT);
    assert!(config.allowed_capabilities.is_empty());
    assert!(!config.audit_enabled);
}

#[test]
fn test_sandbox_config_builder() {
    let config = SandboxConfig::new(8192)
        .with_capability(1)
        .with_capability(2)
        .with_audit()
        .with_quantum_isolation();

    assert_eq!(config.memory_limit, 8192);
    assert!(config.allowed_capabilities.contains(&1));
    assert!(config.allowed_capabilities.contains(&2));
    assert!(config.audit_enabled);
    assert!(config.quantum_isolation);
}

#[test]
fn test_sandbox_config_page_count() {
    let config = SandboxConfig::new(4096);
    assert_eq!(config.page_count(), 1);

    let config = SandboxConfig::new(4097);
    assert_eq!(config.page_count(), 2);
}

#[test]
fn test_sandbox_state_has_capability() {
    let state = SandboxState::new(1, 0x1000, 4096, alloc::vec![1, 2, 3]);
    assert!(state.has_capability(1));
    assert!(state.has_capability(2));
    assert!(!state.has_capability(4));
}

#[test]
fn test_sandbox_error_errno() {
    assert_eq!(SandboxError::ZeroMemoryLimit.to_errno(), -22);
    assert_eq!(SandboxError::AllocationFailed.to_errno(), -12);
    assert_eq!(SandboxError::SandboxNotFound.to_errno(), -2);
}
