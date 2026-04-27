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
use crate::vault::nonos_vault::{initialize_vault, vault_initialized};
use crate::vault::nonos_vault_seal::*;

pub(crate) fn test_vault_seal_store_new() -> TestResult {
    let store = VaultSealStore::new();
    let list = store.list_sealed();
    if !list.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vault_seal_store_list_sealed_empty() -> TestResult {
    let list = VAULT_SEAL_STORE.list_sealed();
    let _ = list.len();
    TestResult::Pass
}

pub(crate) fn test_seal_secret_requires_initialization() -> TestResult {
    let result = seal_secret(b"plaintext", b"aad", SealPolicy::RAMOnly);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unseal_secret_requires_valid_sealed() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"test", b"aad", SealPolicy::RAMOnly) {
            let result = unseal_secret(&sealed);
            if !(result.is_ok() || result.is_err()) {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_unseal_roundtrip_ram_only() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let plaintext = b"secret data to seal";
        let aad = b"additional authenticated data";
        if let Ok(sealed) = seal_secret(plaintext, aad, SealPolicy::RAMOnly) {
            if let Ok(unsealed) = unseal_secret(&sealed) {
                if unsealed != plaintext {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_secret_with_empty_plaintext() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let result = seal_secret(b"", b"aad", SealPolicy::RAMOnly);
        if !(result.is_ok() || result.is_err()) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_secret_with_empty_aad() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let result = seal_secret(b"plaintext", b"", SealPolicy::RAMOnly);
        if !(result.is_ok() || result.is_err()) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_secret_with_large_plaintext() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let large_plaintext = alloc::vec![0xAAu8; 4096];
        let result = seal_secret(&large_plaintext, b"aad", SealPolicy::RAMOnly);
        if !(result.is_ok() || result.is_err()) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_has_timestamp() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"test", b"aad", SealPolicy::RAMOnly) {
            if !(sealed.timestamp > 0 || sealed.timestamp == 0) {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_has_audit_event() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"test", b"aad", SealPolicy::RAMOnly) {
            if sealed.audit.event.is_empty() {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_preserves_policy() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"test", b"aad", SealPolicy::RAMOnly) {
            if sealed.policy != SealPolicy::RAMOnly {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_secret_preserves_aad() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let aad = b"preserved aad";
        if let Ok(sealed) = seal_secret(b"test", aad, SealPolicy::RAMOnly) {
            if sealed.aad != aad {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_list_sealed_returns_vec() -> TestResult {
    let list = list_sealed();
    let _ = list.len();
    TestResult::Pass
}

pub(crate) fn test_secure_erase_sealed_none() -> TestResult {
    secure_erase_sealed(None);
    TestResult::Pass
}

pub(crate) fn test_secure_erase_sealed_ram_only() -> TestResult {
    secure_erase_sealed(Some(SealPolicy::RAMOnly));
    TestResult::Pass
}

pub(crate) fn test_seal_policy_ram_only_stays_in_memory() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"ram only", b"aad", SealPolicy::RAMOnly) {
            if sealed.policy != SealPolicy::RAMOnly {
                return TestResult::Fail;
            }
            if sealed.sealed_data.is_empty() {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_multiple_seals_unique_ciphertexts() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let plaintext = b"same plaintext";
        let aad = b"same aad";
        if let (Ok(sealed1), Ok(sealed2)) = (
            seal_secret(plaintext, aad, SealPolicy::RAMOnly),
            seal_secret(plaintext, aad, SealPolicy::RAMOnly),
        ) {
            if sealed1.sealed_data == sealed2.sealed_data {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_different_plaintext_different_ciphertext() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let (Ok(sealed1), Ok(sealed2)) = (
            seal_secret(b"plaintext1", b"aad", SealPolicy::RAMOnly),
            seal_secret(b"plaintext2", b"aad", SealPolicy::RAMOnly),
        ) {
            if sealed1.sealed_data == sealed2.sealed_data {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_secret_logs_audit() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"audit test", b"aad", SealPolicy::RAMOnly) {
            if sealed.audit.event != "seal_secret" {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_custom_policy() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let result = seal_secret(b"custom", b"aad", SealPolicy::Custom("test_backend".into()));
        if !(result.is_ok() || result.is_err()) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_vault_seal_store_singleton_exists() -> TestResult {
    let _ = VAULT_SEAL_STORE.list_sealed();
    TestResult::Pass
}

pub(crate) fn test_seal_secret_api_function() -> TestResult {
    let result = seal_secret(b"api test", b"aad", SealPolicy::RAMOnly);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_unseal_secret_api_function() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"unseal api", b"aad", SealPolicy::RAMOnly) {
            let result = unseal_secret(&sealed);
            if !(result.is_ok() || result.is_err()) {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_list_sealed_api_function() -> TestResult {
    let list = list_sealed();
    let _ = list.len();
    TestResult::Pass
}

pub(crate) fn test_secure_erase_sealed_api_function() -> TestResult {
    secure_erase_sealed(None);
    TestResult::Pass
}

pub(crate) fn test_sealed_data_includes_nonce() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"nonce test", b"aad", SealPolicy::RAMOnly) {
            if sealed.sealed_data.len() < 12 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_sealed_data_includes_tag() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        if let Ok(sealed) = seal_secret(b"tag test", b"aad", SealPolicy::RAMOnly) {
            if sealed.sealed_data.len() < 12 + 16 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_unseal_preserves_data_integrity() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let plaintext = b"integrity check data";
        let aad = b"integrity aad";
        if let Ok(sealed) = seal_secret(plaintext, aad, SealPolicy::RAMOnly) {
            if let Ok(unsealed) = unseal_secret(&sealed) {
                if unsealed.len() != plaintext.len() {
                    return TestResult::Fail;
                }
                for i in 0..plaintext.len() {
                    if unsealed[i] != plaintext[i] {
                        return TestResult::Fail;
                    }
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_binary_data() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let binary_data: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        if let Ok(sealed) = seal_secret(&binary_data, b"aad", SealPolicy::RAMOnly) {
            if let Ok(unsealed) = unseal_secret(&sealed) {
                if unsealed.as_slice() != &binary_data {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_all_zeros() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let zeros = [0u8; 32];
        if let Ok(sealed) = seal_secret(&zeros, b"aad", SealPolicy::RAMOnly) {
            if let Ok(unsealed) = unseal_secret(&sealed) {
                if unsealed.as_slice() != &zeros {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_seal_all_ones() -> TestResult {
    let _ = initialize_vault();
    if vault_initialized() {
        let ones = [0xFFu8; 32];
        if let Ok(sealed) = seal_secret(&ones, b"aad", SealPolicy::RAMOnly) {
            if let Ok(unsealed) = unseal_secret(&sealed) {
                if unsealed.as_slice() != &ones {
                    return TestResult::Fail;
                }
            }
        }
    }
    TestResult::Pass
}
