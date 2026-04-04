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

extern crate alloc;

use crate::vault::nonos_vault_seal::{SealPolicy, SealedSecret};
use crate::vault::nonos_vault::VaultAuditEvent;

#[test]
fn test_seal_policy_ram_only_eq() {
    assert_eq!(SealPolicy::RAMOnly, SealPolicy::RAMOnly);
}

#[test]
fn test_seal_policy_uefi_eq() {
    assert_eq!(SealPolicy::UEFI, SealPolicy::UEFI);
}

#[test]
fn test_seal_policy_disk_eq() {
    assert_eq!(SealPolicy::Disk, SealPolicy::Disk);
}

#[test]
fn test_seal_policy_custom_eq() {
    let p1 = SealPolicy::Custom("backend".into());
    let p2 = SealPolicy::Custom("backend".into());
    assert_eq!(p1, p2);
}

#[test]
fn test_seal_policy_custom_ne_different_backend() {
    let p1 = SealPolicy::Custom("backend1".into());
    let p2 = SealPolicy::Custom("backend2".into());
    assert_ne!(p1, p2);
}

#[test]
fn test_seal_policy_different_variants_ne() {
    assert_ne!(SealPolicy::RAMOnly, SealPolicy::UEFI);
    assert_ne!(SealPolicy::UEFI, SealPolicy::Disk);
    assert_ne!(SealPolicy::Disk, SealPolicy::RAMOnly);
}

#[test]
fn test_seal_policy_clone() {
    let p1 = SealPolicy::UEFI;
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn test_seal_policy_custom_clone() {
    let p1 = SealPolicy::Custom("my_backend".into());
    let p2 = p1.clone();
    assert_eq!(p1, p2);
}

#[test]
fn test_seal_policy_debug_ram_only() {
    let p = SealPolicy::RAMOnly;
    let debug = alloc::format!("{:?}", p);
    assert!(debug.contains("RAMOnly"));
}

#[test]
fn test_seal_policy_debug_uefi() {
    let p = SealPolicy::UEFI;
    let debug = alloc::format!("{:?}", p);
    assert!(debug.contains("UEFI"));
}

#[test]
fn test_seal_policy_debug_disk() {
    let p = SealPolicy::Disk;
    let debug = alloc::format!("{:?}", p);
    assert!(debug.contains("Disk"));
}

#[test]
fn test_seal_policy_debug_custom() {
    let p = SealPolicy::Custom("test_backend".into());
    let debug = alloc::format!("{:?}", p);
    assert!(debug.contains("Custom"));
    assert!(debug.contains("test_backend"));
}

#[test]
fn test_sealed_secret_clone() {
    let audit = VaultAuditEvent {
        timestamp: 12345,
        event: "seal".into(),
        context: Some("test".into()),
        status: Some("ok".into()),
    };
    let secret = SealedSecret {
        sealed_data: alloc::vec![1, 2, 3, 4],
        aad: alloc::vec![5, 6, 7, 8],
        policy: SealPolicy::RAMOnly,
        timestamp: 12345,
        audit: audit,
    };
    let cloned = secret.clone();
    assert_eq!(secret.sealed_data, cloned.sealed_data);
    assert_eq!(secret.aad, cloned.aad);
    assert_eq!(secret.policy, cloned.policy);
    assert_eq!(secret.timestamp, cloned.timestamp);
}

#[test]
fn test_sealed_secret_debug() {
    let audit = VaultAuditEvent {
        timestamp: 1000,
        event: "seal".into(),
        context: None,
        status: None,
    };
    let secret = SealedSecret {
        sealed_data: alloc::vec![0xAA, 0xBB],
        aad: alloc::vec![0xCC],
        policy: SealPolicy::Disk,
        timestamp: 1000,
        audit: audit,
    };
    let debug = alloc::format!("{:?}", secret);
    assert!(debug.contains("SealedSecret"));
    assert!(debug.contains("Disk"));
}

#[test]
fn test_sealed_secret_empty_data() {
    let audit = VaultAuditEvent {
        timestamp: 0,
        event: "empty".into(),
        context: None,
        status: None,
    };
    let secret = SealedSecret {
        sealed_data: alloc::vec![],
        aad: alloc::vec![],
        policy: SealPolicy::RAMOnly,
        timestamp: 0,
        audit: audit,
    };
    assert!(secret.sealed_data.is_empty());
    assert!(secret.aad.is_empty());
}

#[test]
fn test_sealed_secret_large_data() {
    let audit = VaultAuditEvent {
        timestamp: 0,
        event: "large".into(),
        context: None,
        status: None,
    };
    let large_data = alloc::vec![0u8; 1024];
    let secret = SealedSecret {
        sealed_data: large_data.clone(),
        aad: alloc::vec![1, 2, 3],
        policy: SealPolicy::UEFI,
        timestamp: 999,
        audit: audit,
    };
    assert_eq!(secret.sealed_data.len(), 1024);
}

#[test]
fn test_sealed_secret_with_custom_policy() {
    let audit = VaultAuditEvent {
        timestamp: 0,
        event: "custom".into(),
        context: None,
        status: None,
    };
    let secret = SealedSecret {
        sealed_data: alloc::vec![1],
        aad: alloc::vec![2],
        policy: SealPolicy::Custom("tpm2".into()),
        timestamp: 555,
        audit: audit,
    };
    if let SealPolicy::Custom(backend) = &secret.policy {
        assert_eq!(backend, "tpm2");
    } else {
        panic!("Expected Custom policy");
    }
}

#[test]
fn test_sealed_secret_audit_event_preserved() {
    let audit = VaultAuditEvent {
        timestamp: 42,
        event: "audit_check".into(),
        context: Some("preserve_ctx".into()),
        status: Some("preserved".into()),
    };
    let secret = SealedSecret {
        sealed_data: alloc::vec![],
        aad: alloc::vec![],
        policy: SealPolicy::RAMOnly,
        timestamp: 42,
        audit: audit,
    };
    assert_eq!(secret.audit.timestamp, 42);
    assert_eq!(secret.audit.event, "audit_check");
    assert_eq!(secret.audit.context.as_ref().unwrap(), "preserve_ctx");
}
