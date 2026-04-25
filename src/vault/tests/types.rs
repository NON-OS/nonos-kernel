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

use crate::test::framework::TestResult;
use crate::vault::nonos_vault::VaultAuditEvent;
use crate::vault::nonos_vault_seal::{SealPolicy, SealedSecret};

pub(crate) fn test_seal_policy_ram_only_eq() -> TestResult {
    if SealPolicy::RAMOnly != SealPolicy::RAMOnly {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_uefi_eq() -> TestResult {
    if SealPolicy::UEFI != SealPolicy::UEFI {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_disk_eq() -> TestResult {
    if SealPolicy::Disk != SealPolicy::Disk {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_custom_eq() -> TestResult {
    let p1 = SealPolicy::Custom("backend".into());
    let p2 = SealPolicy::Custom("backend".into());
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_custom_ne_different_backend() -> TestResult {
    let p1 = SealPolicy::Custom("backend1".into());
    let p2 = SealPolicy::Custom("backend2".into());
    if p1 == p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_different_variants_ne() -> TestResult {
    if SealPolicy::RAMOnly == SealPolicy::UEFI {
        return TestResult::Fail;
    }
    if SealPolicy::UEFI == SealPolicy::Disk {
        return TestResult::Fail;
    }
    if SealPolicy::Disk == SealPolicy::RAMOnly {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_clone() -> TestResult {
    let p1 = SealPolicy::UEFI;
    let p2 = p1.clone();
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_custom_clone() -> TestResult {
    let p1 = SealPolicy::Custom("my_backend".into());
    let p2 = p1.clone();
    if p1 != p2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_debug_ram_only() -> TestResult {
    let p = SealPolicy::RAMOnly;
    let debug = alloc::format!("{:?}", p);
    if !debug.contains("RAMOnly") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_debug_uefi() -> TestResult {
    let p = SealPolicy::UEFI;
    let debug = alloc::format!("{:?}", p);
    if !debug.contains("UEFI") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_debug_disk() -> TestResult {
    let p = SealPolicy::Disk;
    let debug = alloc::format!("{:?}", p);
    if !debug.contains("Disk") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_seal_policy_debug_custom() -> TestResult {
    let p = SealPolicy::Custom("test_backend".into());
    let debug = alloc::format!("{:?}", p);
    if !debug.contains("Custom") {
        return TestResult::Fail;
    }
    if !debug.contains("test_backend") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_clone() -> TestResult {
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
    if secret.sealed_data != cloned.sealed_data {
        return TestResult::Fail;
    }
    if secret.aad != cloned.aad {
        return TestResult::Fail;
    }
    if secret.policy != cloned.policy {
        return TestResult::Fail;
    }
    if secret.timestamp != cloned.timestamp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_debug() -> TestResult {
    let audit =
        VaultAuditEvent { timestamp: 1000, event: "seal".into(), context: None, status: None };
    let secret = SealedSecret {
        sealed_data: alloc::vec![0xAA, 0xBB],
        aad: alloc::vec![0xCC],
        policy: SealPolicy::Disk,
        timestamp: 1000,
        audit: audit,
    };
    let debug = alloc::format!("{:?}", secret);
    if !debug.contains("SealedSecret") {
        return TestResult::Fail;
    }
    if !debug.contains("Disk") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_empty_data() -> TestResult {
    let audit =
        VaultAuditEvent { timestamp: 0, event: "empty".into(), context: None, status: None };
    let secret = SealedSecret {
        sealed_data: alloc::vec![],
        aad: alloc::vec![],
        policy: SealPolicy::RAMOnly,
        timestamp: 0,
        audit: audit,
    };
    if !secret.sealed_data.is_empty() {
        return TestResult::Fail;
    }
    if !secret.aad.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_large_data() -> TestResult {
    let audit =
        VaultAuditEvent { timestamp: 0, event: "large".into(), context: None, status: None };
    let large_data = alloc::vec![0u8; 1024];
    let secret = SealedSecret {
        sealed_data: large_data.clone(),
        aad: alloc::vec![1, 2, 3],
        policy: SealPolicy::UEFI,
        timestamp: 999,
        audit: audit,
    };
    if secret.sealed_data.len() != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_with_custom_policy() -> TestResult {
    let audit =
        VaultAuditEvent { timestamp: 0, event: "custom".into(), context: None, status: None };
    let secret = SealedSecret {
        sealed_data: alloc::vec![1],
        aad: alloc::vec![2],
        policy: SealPolicy::Custom("tpm2".into()),
        timestamp: 555,
        audit: audit,
    };
    if let SealPolicy::Custom(backend) = &secret.policy {
        if backend != "tpm2" {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_audit_event_preserved() -> TestResult {
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
    if secret.audit.timestamp != 42 {
        return TestResult::Fail;
    }
    if secret.audit.event != "audit_check" {
        return TestResult::Fail;
    }
    if secret.audit.context.as_ref().unwrap() != "preserve_ctx" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
