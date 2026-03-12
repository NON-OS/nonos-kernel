// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use uefi::cstr16;
use uefi::prelude::*;

use crate::crypto::sig::{init_production_keys, is_initialized, verify_signature_bytes, VerifyError};
use crate::log::logger::{log_debug, log_error, log_info};

use super::display::{mini_delay, print, print_hex_bytes};
use super::types::{CryptoVerifyResult, MIN_KERNEL_SIZE};

pub fn initialize_crypto_if_needed(st: &mut SystemTable<Boot>) -> bool {
    if is_initialized() {
        return true;
    }

    print(st, cstr16!("  [CRYPTO] Initializing keystore...\r\n"));

    if let Err(_) = init_production_keys() {
        log_error("crypto_real", "Failed to initialize production keys");
        print(st, cstr16!("  [CRYPTO] Keystore init ........................ [FAIL]\r\n"));
        return false;
    }

    print(st, cstr16!("  [CRYPTO] Keystore initialized ................ [  OK  ]\r\n"));
    true
}

pub fn validate_kernel_size(kernel_data: &[u8], st: &mut SystemTable<Boot>) -> bool {
    if kernel_data.len() < MIN_KERNEL_SIZE {
        log_error("crypto_real", "Kernel too small - no room for signature");
        print(st, cstr16!("  [CRYPTO] Kernel size check .................... [FAIL]\r\n"));
        print(st, cstr16!("  [CRYPTO] ERROR: Kernel too small for signature\r\n"));
        return false;
    }
    true
}

pub fn compute_and_display_hash(
    kernel_code: &[u8],
    result: &mut CryptoVerifyResult,
    st: &mut SystemTable<Boot>,
) {
    print(st, cstr16!("  [CRYPTO] Computing BLAKE3 hash...\r\n"));
    mini_delay();

    let hash = blake3::hash(kernel_code);
    let hash_bytes = hash.as_bytes();

    result.kernel_hash_full.copy_from_slice(hash_bytes);
    result.kernel_hash_preview.copy_from_slice(&hash_bytes[..8]);

    log_debug("kernel_verify", "BLAKE3 hash computed");

    print(st, cstr16!("  [CRYPTO] BLAKE3: "));
    print_hex_bytes(st, &hash_bytes[..8]);
    print(st, cstr16!("...\r\n"));
    mini_delay();
}

pub fn verify_and_display_signature(
    kernel_code: &[u8],
    signature: &[u8],
    result: &mut CryptoVerifyResult,
    st: &mut SystemTable<Boot>,
) {
    print(st, cstr16!("  [CRYPTO] Extracting Ed25519 signature...\r\n"));
    mini_delay();

    if signature.iter().all(|&b| b == 0) {
        log_error("crypto_real", "Signature is all zeros - kernel unsigned");
        print(st, cstr16!("  [CRYPTO] Signature: ALL ZEROS (UNSIGNED!)\r\n"));
        print(st, cstr16!("  [CRYPTO] Ed25519 verify ....................... [FAIL]\r\n"));
        return;
    }

    display_signature_components(signature, st);
    print(st, cstr16!("  [CRYPTO] Verifying Ed25519 signature...\r\n"));

    match verify_signature_bytes(kernel_code, signature) {
        Ok(key_id) => {
            result.signature_valid = true;
            log_info("kernel_verify", "Ed25519 signature VERIFIED against trusted key");
            print(st, cstr16!("  [CRYPTO] Ed25519 verify ....................... [PASS]\r\n"));
            mini_delay();
            print(st, cstr16!("  [CRYPTO] Signer key ID: "));
            print_hex_bytes(st, &key_id[0..8]);
            print(st, cstr16!("...\r\n"));
        }
        Err(e) => {
            result.signature_valid = false;
            log_error("kernel_verify", "Ed25519 signature verification FAILED");
            print(st, cstr16!("  [CRYPTO] Ed25519 verify ....................... [FAIL]\r\n"));
            display_verification_error(e, st);
        }
    }

    mini_delay();
}

fn display_signature_components(signature: &[u8], st: &mut SystemTable<Boot>) {
    print(st, cstr16!("  [CRYPTO] Sig R: "));
    print_hex_bytes(st, &signature[0..8]);
    print(st, cstr16!("...\r\n"));

    print(st, cstr16!("  [CRYPTO] Sig S: "));
    print_hex_bytes(st, &signature[32..40]);
    print(st, cstr16!("...\r\n"));
    mini_delay();
}

fn display_verification_error(e: VerifyError, st: &mut SystemTable<Boot>) {
    match e {
        VerifyError::InvalidSignature => {
            print(st, cstr16!("  [CRYPTO] ERROR: Signature does not match any trusted key\r\n"));
        }
        VerifyError::KeyNotFound => {
            print(st, cstr16!("  [CRYPTO] ERROR: Signing key not in trusted keystore\r\n"));
        }
        VerifyError::NotInitialized => {
            print(st, cstr16!("  [CRYPTO] ERROR: Keystore not initialized\r\n"));
        }
        VerifyError::MalformedSignature => {
            print(st, cstr16!("  [CRYPTO] ERROR: Malformed signature data\r\n"));
        }
        VerifyError::Bounds => {
            print(st, cstr16!("  [CRYPTO] ERROR: Signature bounds error\r\n"));
        }
        VerifyError::KeyRevoked => {
            print(st, cstr16!("  [CRYPTO] ERROR: Signing key has been revoked\r\n"));
        }
        VerifyError::KeyVersionTooOld => {
            print(st, cstr16!("  [CRYPTO] ERROR: Key version below minimum required\r\n"));
        }
    }
}
