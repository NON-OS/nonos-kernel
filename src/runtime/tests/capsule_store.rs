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

use crate::runtime::*;

#[test]
fn test_capsule_category_system() {
    let category = capsule_store::CapsuleCategory::System;
    assert_eq!(category, capsule_store::CapsuleCategory::System);
}

#[test]
fn test_capsule_category_privacy() {
    let category = capsule_store::CapsuleCategory::Privacy;
    assert_eq!(category, capsule_store::CapsuleCategory::Privacy);
}

#[test]
fn test_capsule_category_security() {
    let category = capsule_store::CapsuleCategory::Security;
    assert_eq!(category, capsule_store::CapsuleCategory::Security);
}

#[test]
fn test_capsule_category_network() {
    let category = capsule_store::CapsuleCategory::Network;
    assert_eq!(category, capsule_store::CapsuleCategory::Network);
}

#[test]
fn test_capsule_category_utility() {
    let category = capsule_store::CapsuleCategory::Utility;
    assert_eq!(category, capsule_store::CapsuleCategory::Utility);
}

#[test]
fn test_capsule_category_development() {
    let category = capsule_store::CapsuleCategory::Development;
    assert_eq!(category, capsule_store::CapsuleCategory::Development);
}

#[test]
fn test_capsule_category_media() {
    let category = capsule_store::CapsuleCategory::Media;
    assert_eq!(category, capsule_store::CapsuleCategory::Media);
}

#[test]
fn test_capsule_category_finance() {
    let category = capsule_store::CapsuleCategory::Finance;
    assert_eq!(category, capsule_store::CapsuleCategory::Finance);
}

#[test]
fn test_capsule_category_communication() {
    let category = capsule_store::CapsuleCategory::Communication;
    assert_eq!(category, capsule_store::CapsuleCategory::Communication);
}

#[test]
fn test_capsule_category_clone() {
    let c1 = capsule_store::CapsuleCategory::System;
    let c2 = c1.clone();
    assert_eq!(c1, c2);
}

#[test]
fn test_capsule_category_copy() {
    let c1 = capsule_store::CapsuleCategory::Privacy;
    let c2 = c1;
    assert_eq!(c1, c2);
}

#[test]
fn test_capsule_category_debug() {
    let category = capsule_store::CapsuleCategory::Security;
    let debug_str = alloc::format!("{:?}", category);
    assert!(debug_str.contains("Security"));
}

#[test]
fn test_capsule_category_all_unique() {
    let categories = [
        capsule_store::CapsuleCategory::System,
        capsule_store::CapsuleCategory::Privacy,
        capsule_store::CapsuleCategory::Security,
        capsule_store::CapsuleCategory::Network,
        capsule_store::CapsuleCategory::Utility,
        capsule_store::CapsuleCategory::Development,
        capsule_store::CapsuleCategory::Media,
        capsule_store::CapsuleCategory::Finance,
        capsule_store::CapsuleCategory::Communication,
    ];
    for i in 0..categories.len() {
        for j in (i + 1)..categories.len() {
            assert_ne!(categories[i], categories[j]);
        }
    }
}

#[test]
fn test_install_state_pending() {
    let state = capsule_store::InstallState::Pending;
    assert_eq!(state, capsule_store::InstallState::Pending);
}

#[test]
fn test_install_state_payment_required() {
    let state = capsule_store::InstallState::PaymentRequired;
    assert_eq!(state, capsule_store::InstallState::PaymentRequired);
}

#[test]
fn test_install_state_payment_submitted() {
    let state = capsule_store::InstallState::PaymentSubmitted;
    assert_eq!(state, capsule_store::InstallState::PaymentSubmitted);
}

#[test]
fn test_install_state_payment_confirmed() {
    let state = capsule_store::InstallState::PaymentConfirmed;
    assert_eq!(state, capsule_store::InstallState::PaymentConfirmed);
}

#[test]
fn test_install_state_downloading() {
    let state = capsule_store::InstallState::Downloading;
    assert_eq!(state, capsule_store::InstallState::Downloading);
}

#[test]
fn test_install_state_verifying() {
    let state = capsule_store::InstallState::Verifying;
    assert_eq!(state, capsule_store::InstallState::Verifying);
}

#[test]
fn test_install_state_installing() {
    let state = capsule_store::InstallState::Installing;
    assert_eq!(state, capsule_store::InstallState::Installing);
}

#[test]
fn test_install_state_installed() {
    let state = capsule_store::InstallState::Installed;
    assert_eq!(state, capsule_store::InstallState::Installed);
}

#[test]
fn test_install_state_failed() {
    let state = capsule_store::InstallState::Failed;
    assert_eq!(state, capsule_store::InstallState::Failed);
}

#[test]
fn test_install_state_clone() {
    let s1 = capsule_store::InstallState::Pending;
    let s2 = s1.clone();
    assert_eq!(s1, s2);
}

#[test]
fn test_install_state_copy() {
    let s1 = capsule_store::InstallState::Installed;
    let s2 = s1;
    assert_eq!(s1, s2);
}

#[test]
fn test_install_state_debug() {
    let state = capsule_store::InstallState::Downloading;
    let debug_str = alloc::format!("{:?}", state);
    assert!(debug_str.contains("Downloading"));
}

#[test]
fn test_install_state_all_unique() {
    let states = [
        capsule_store::InstallState::Pending,
        capsule_store::InstallState::PaymentRequired,
        capsule_store::InstallState::PaymentSubmitted,
        capsule_store::InstallState::PaymentConfirmed,
        capsule_store::InstallState::Downloading,
        capsule_store::InstallState::Verifying,
        capsule_store::InstallState::Installing,
        capsule_store::InstallState::Installed,
        capsule_store::InstallState::Failed,
    ];
    for i in 0..states.len() {
        for j in (i + 1)..states.len() {
            assert_ne!(states[i], states[j]);
        }
    }
}

#[test]
fn test_capsule_metadata_clone() {
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("test"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("test capsule"),
        author: alloc::string::String::from("test author"),
        category: capsule_store::CapsuleCategory::System,
        size_bytes: 1024,
        nox_fee: 0,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    let cloned = meta.clone();
    assert_eq!(meta.name, cloned.name);
    assert_eq!(meta.version, cloned.version);
    assert_eq!(meta.category, cloned.category);
}

#[test]
fn test_capsule_metadata_debug() {
    let meta = capsule_store::CapsuleMetadata {
        id: [1u8; 32],
        name: alloc::string::String::from("debug_test"),
        version: alloc::string::String::from("2.0.0"),
        description: alloc::string::String::from("debug test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::Privacy,
        size_bytes: 2048,
        nox_fee: 100,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    let debug_str = alloc::format!("{:?}", meta);
    assert!(debug_str.contains("debug_test"));
}

#[test]
fn test_installation_task_clone() {
    let task = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Pending,
        tx_hash: None,
        progress_percent: 0,
        error: None,
    };
    let cloned = task.clone();
    assert_eq!(task.capsule_id, cloned.capsule_id);
    assert_eq!(task.state, cloned.state);
    assert_eq!(task.progress_percent, cloned.progress_percent);
}

#[test]
fn test_installation_task_debug() {
    let task = capsule_store::InstallationTask {
        capsule_id: [1u8; 32],
        state: capsule_store::InstallState::Installing,
        tx_hash: Some([2u8; 32]),
        progress_percent: 50,
        error: None,
    };
    let debug_str = alloc::format!("{:?}", task);
    assert!(debug_str.contains("InstallationTask"));
}

#[test]
fn test_installation_task_with_error() {
    let task = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Failed,
        tx_hash: None,
        progress_percent: 0,
        error: Some(alloc::string::String::from("test error")),
    };
    assert!(task.error.is_some());
    assert_eq!(task.error.unwrap(), "test error");
}

#[test]
fn test_installation_task_with_tx_hash() {
    let hash = [42u8; 32];
    let task = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::PaymentConfirmed,
        tx_hash: Some(hash),
        progress_percent: 25,
        error: None,
    };
    assert!(task.tx_hash.is_some());
    assert_eq!(task.tx_hash.unwrap(), hash);
}

#[test]
fn test_micro_fee_nox_constant() {
    assert_eq!(capsule_store::MICRO_FEE_NOX, 1_000_000_000_000_000);
}

#[test]
fn test_gas_price_gwei_constant() {
    assert_eq!(capsule_store::GAS_PRICE_GWEI, 20);
}

#[test]
fn test_mainnet_chain_id_constant() {
    assert_eq!(capsule_store::MAINNET_CHAIN_ID, 1);
}

#[test]
fn test_format_nox_amount_zero() {
    let result = capsule_store::format_nox_amount(0);
    assert_eq!(result, "0.000 NOX");
}

#[test]
fn test_format_nox_amount_one_wei() {
    let result = capsule_store::format_nox_amount(1);
    assert_eq!(result, "0.000 NOX");
}

#[test]
fn test_format_nox_amount_one_nox() {
    let result = capsule_store::format_nox_amount(1_000_000_000_000_000_000);
    assert_eq!(result, "1.000 NOX");
}

#[test]
fn test_format_nox_amount_fractional() {
    let result = capsule_store::format_nox_amount(1_500_000_000_000_000_000);
    assert_eq!(result, "1.500 NOX");
}

#[test]
fn test_format_nox_amount_large() {
    let result = capsule_store::format_nox_amount(100_000_000_000_000_000_000);
    assert_eq!(result, "100.000 NOX");
}

#[test]
fn test_format_nox_amount_micro_fee() {
    let result = capsule_store::format_nox_amount(capsule_store::MICRO_FEE_NOX);
    assert_eq!(result, "0.001 NOX");
}

#[test]
fn test_installed_capsule_clone() {
    use core::sync::atomic::AtomicBool;
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("test"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::System,
        size_bytes: 0,
        nox_fee: 0,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    let installed = capsule_store::InstalledCapsule {
        metadata: meta,
        install_timestamp: 12345,
        code_hash: [1u8; 32],
        active: AtomicBool::new(true),
    };
    let cloned = installed.clone();
    assert_eq!(installed.install_timestamp, cloned.install_timestamp);
    assert_eq!(installed.code_hash, cloned.code_hash);
}

#[test]
fn test_installed_capsule_debug() {
    use core::sync::atomic::AtomicBool;
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("debug_capsule"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::System,
        size_bytes: 0,
        nox_fee: 0,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    let installed = capsule_store::InstalledCapsule {
        metadata: meta,
        install_timestamp: 12345,
        code_hash: [1u8; 32],
        active: AtomicBool::new(true),
    };
    let debug_str = alloc::format!("{:?}", installed);
    assert!(debug_str.contains("InstalledCapsule"));
}

#[test]
fn test_capsule_metadata_with_dilithium_signature() {
    let sig = alloc::vec![1u8, 2, 3, 4, 5];
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("pq_test"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("post-quantum test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::Security,
        size_bytes: 4096,
        nox_fee: 0,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: Some(sig.clone()),
    };
    assert!(meta.dilithium_signature.is_some());
    assert_eq!(meta.dilithium_signature.unwrap(), sig);
}

#[test]
fn test_capsule_metadata_without_dilithium_signature() {
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("classic_test"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("classic test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::System,
        size_bytes: 2048,
        nox_fee: 0,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    assert!(meta.dilithium_signature.is_none());
}

#[test]
fn test_installation_task_progress_bounds() {
    let task_0 = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Pending,
        tx_hash: None,
        progress_percent: 0,
        error: None,
    };
    assert_eq!(task_0.progress_percent, 0);

    let task_100 = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Installed,
        tx_hash: None,
        progress_percent: 100,
        error: None,
    };
    assert_eq!(task_100.progress_percent, 100);
}

#[test]
fn test_capsule_metadata_size_bytes() {
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("size_test"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("size test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::Utility,
        size_bytes: 1024 * 1024 * 10,
        nox_fee: 0,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    assert_eq!(meta.size_bytes, 10485760);
}

#[test]
fn test_capsule_metadata_nox_fee() {
    let meta = capsule_store::CapsuleMetadata {
        id: [0u8; 32],
        name: alloc::string::String::from("fee_test"),
        version: alloc::string::String::from("1.0.0"),
        description: alloc::string::String::from("fee test"),
        author: alloc::string::String::from("author"),
        category: capsule_store::CapsuleCategory::Finance,
        size_bytes: 0,
        nox_fee: capsule_store::MICRO_FEE_NOX * 5,
        signature: [0u8; 64],
        ed25519_pubkey: [0u8; 32],
        dilithium_signature: None,
    };
    assert_eq!(meta.nox_fee, capsule_store::MICRO_FEE_NOX * 5);
}
