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
use crate::test::framework::TestResult;

pub(crate) fn test_capsule_category_system() -> TestResult {
    let category = capsule_store::CapsuleCategory::System;
    if category != capsule_store::CapsuleCategory::System {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_privacy() -> TestResult {
    let category = capsule_store::CapsuleCategory::Privacy;
    if category != capsule_store::CapsuleCategory::Privacy {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_security() -> TestResult {
    let category = capsule_store::CapsuleCategory::Security;
    if category != capsule_store::CapsuleCategory::Security {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_network() -> TestResult {
    let category = capsule_store::CapsuleCategory::Network;
    if category != capsule_store::CapsuleCategory::Network {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_utility() -> TestResult {
    let category = capsule_store::CapsuleCategory::Utility;
    if category != capsule_store::CapsuleCategory::Utility {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_development() -> TestResult {
    let category = capsule_store::CapsuleCategory::Development;
    if category != capsule_store::CapsuleCategory::Development {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_media() -> TestResult {
    let category = capsule_store::CapsuleCategory::Media;
    if category != capsule_store::CapsuleCategory::Media {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_finance() -> TestResult {
    let category = capsule_store::CapsuleCategory::Finance;
    if category != capsule_store::CapsuleCategory::Finance {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_communication() -> TestResult {
    let category = capsule_store::CapsuleCategory::Communication;
    if category != capsule_store::CapsuleCategory::Communication {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_clone() -> TestResult {
    let c1 = capsule_store::CapsuleCategory::System;
    let c2 = c1.clone();
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_copy() -> TestResult {
    let c1 = capsule_store::CapsuleCategory::Privacy;
    let c2 = c1;
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_debug() -> TestResult {
    let category = capsule_store::CapsuleCategory::Security;
    let debug_str = alloc::format!("{:?}", category);
    if !debug_str.contains("Security") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_category_all_unique() -> TestResult {
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
            if categories[i] == categories[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_pending() -> TestResult {
    let state = capsule_store::InstallState::Pending;
    if state != capsule_store::InstallState::Pending {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_payment_required() -> TestResult {
    let state = capsule_store::InstallState::PaymentRequired;
    if state != capsule_store::InstallState::PaymentRequired {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_payment_submitted() -> TestResult {
    let state = capsule_store::InstallState::PaymentSubmitted;
    if state != capsule_store::InstallState::PaymentSubmitted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_payment_confirmed() -> TestResult {
    let state = capsule_store::InstallState::PaymentConfirmed;
    if state != capsule_store::InstallState::PaymentConfirmed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_downloading() -> TestResult {
    let state = capsule_store::InstallState::Downloading;
    if state != capsule_store::InstallState::Downloading {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_verifying() -> TestResult {
    let state = capsule_store::InstallState::Verifying;
    if state != capsule_store::InstallState::Verifying {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_installing() -> TestResult {
    let state = capsule_store::InstallState::Installing;
    if state != capsule_store::InstallState::Installing {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_installed() -> TestResult {
    let state = capsule_store::InstallState::Installed;
    if state != capsule_store::InstallState::Installed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_failed() -> TestResult {
    let state = capsule_store::InstallState::Failed;
    if state != capsule_store::InstallState::Failed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_clone() -> TestResult {
    let s1 = capsule_store::InstallState::Pending;
    let s2 = s1.clone();
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_copy() -> TestResult {
    let s1 = capsule_store::InstallState::Installed;
    let s2 = s1;
    if s1 != s2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_debug() -> TestResult {
    let state = capsule_store::InstallState::Downloading;
    let debug_str = alloc::format!("{:?}", state);
    if !debug_str.contains("Downloading") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_install_state_all_unique() -> TestResult {
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
            if states[i] == states[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_metadata_clone() -> TestResult {
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
    if meta.name != cloned.name {
        return TestResult::Fail;
    }
    if meta.version != cloned.version {
        return TestResult::Fail;
    }
    if meta.category != cloned.category {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_metadata_debug() -> TestResult {
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
    if !debug_str.contains("debug_test") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installation_task_clone() -> TestResult {
    let task = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Pending,
        tx_hash: None,
        progress_percent: 0,
        error: None,
    };
    let cloned = task.clone();
    if task.capsule_id != cloned.capsule_id {
        return TestResult::Fail;
    }
    if task.state != cloned.state {
        return TestResult::Fail;
    }
    if task.progress_percent != cloned.progress_percent {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installation_task_debug() -> TestResult {
    let task = capsule_store::InstallationTask {
        capsule_id: [1u8; 32],
        state: capsule_store::InstallState::Installing,
        tx_hash: Some([2u8; 32]),
        progress_percent: 50,
        error: None,
    };
    let debug_str = alloc::format!("{:?}", task);
    if !debug_str.contains("InstallationTask") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installation_task_with_error() -> TestResult {
    let task = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Failed,
        tx_hash: None,
        progress_percent: 0,
        error: Some(alloc::string::String::from("test error")),
    };
    if !task.error.is_some() {
        return TestResult::Fail;
    }
    if task.error.unwrap() != "test error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installation_task_with_tx_hash() -> TestResult {
    let hash = [42u8; 32];
    let task = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::PaymentConfirmed,
        tx_hash: Some(hash),
        progress_percent: 25,
        error: None,
    };
    if !task.tx_hash.is_some() {
        return TestResult::Fail;
    }
    if task.tx_hash.unwrap() != hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_micro_fee_nox_constant() -> TestResult {
    if capsule_store::MICRO_FEE_NOX != 1_000_000_000_000_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gas_price_gwei_constant() -> TestResult {
    if capsule_store::GAS_PRICE_GWEI != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mainnet_chain_id_constant() -> TestResult {
    if capsule_store::MAINNET_CHAIN_ID != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_nox_amount_zero() -> TestResult {
    let result = capsule_store::format_nox_amount(0);
    if result != "0.000 NOX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_nox_amount_one_wei() -> TestResult {
    let result = capsule_store::format_nox_amount(1);
    if result != "0.000 NOX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_nox_amount_one_nox() -> TestResult {
    let result = capsule_store::format_nox_amount(1_000_000_000_000_000_000);
    if result != "1.000 NOX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_nox_amount_fractional() -> TestResult {
    let result = capsule_store::format_nox_amount(1_500_000_000_000_000_000);
    if result != "1.500 NOX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_nox_amount_large() -> TestResult {
    let result = capsule_store::format_nox_amount(100_000_000_000_000_000_000);
    if result != "100.000 NOX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_format_nox_amount_micro_fee() -> TestResult {
    let result = capsule_store::format_nox_amount(capsule_store::MICRO_FEE_NOX);
    if result != "0.001 NOX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installed_capsule_clone() -> TestResult {
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
    if installed.install_timestamp != cloned.install_timestamp {
        return TestResult::Fail;
    }
    if installed.code_hash != cloned.code_hash {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installed_capsule_debug() -> TestResult {
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
    if !debug_str.contains("InstalledCapsule") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_metadata_with_dilithium_signature() -> TestResult {
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
    if !meta.dilithium_signature.is_some() {
        return TestResult::Fail;
    }
    if meta.dilithium_signature.unwrap() != sig {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_metadata_without_dilithium_signature() -> TestResult {
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
    if !meta.dilithium_signature.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_installation_task_progress_bounds() -> TestResult {
    let task_0 = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Pending,
        tx_hash: None,
        progress_percent: 0,
        error: None,
    };
    if task_0.progress_percent != 0 {
        return TestResult::Fail;
    }

    let task_100 = capsule_store::InstallationTask {
        capsule_id: [0u8; 32],
        state: capsule_store::InstallState::Installed,
        tx_hash: None,
        progress_percent: 100,
        error: None,
    };
    if task_100.progress_percent != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_metadata_size_bytes() -> TestResult {
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
    if meta.size_bytes != 10485760 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_capsule_metadata_nox_fee() -> TestResult {
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
    if meta.nox_fee != capsule_store::MICRO_FEE_NOX * 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
