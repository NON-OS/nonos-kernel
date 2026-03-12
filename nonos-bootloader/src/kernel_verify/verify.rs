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

/*
 * Kernel cryptographic verification.
 *
 * Kernel binary format: [kernel_code][64-byte Ed25519 signature][optional ZK proof]
 *
 * Verification steps:
 * 1. Parse ELF header to find kernel code boundaries
 * 2. Extract signature from bytes after ELF
 * 3. Compute BLAKE3 hash of kernel code
 * 4. Verify Ed25519 signature against trusted keys
 */

use uefi::prelude::*;

use crate::log::logger::{log_debug, log_error, log_info};

use super::display::{mini_delay, print_kernel_size, print_verification_failure, print_verification_success};
use super::elf::{compute_elf_size, find_zk_block_offset};
use super::helpers::{
    compute_and_display_hash, initialize_crypto_if_needed, validate_kernel_size,
    verify_and_display_signature,
};
use super::types::{CryptoVerifyResult, SIGNATURE_SIZE};

pub fn verify_kernel_crypto(kernel_data: &[u8], st: &mut SystemTable<Boot>) -> CryptoVerifyResult {
    log_info("kernel_verify", "Starting cryptographic verification");

    let mut result = CryptoVerifyResult::new();

    if !initialize_crypto_if_needed(st) {
        return result;
    }

    if !validate_kernel_size(kernel_data, st) {
        return result;
    }

    let kernel_code_end = determine_kernel_boundary(kernel_data);
    if kernel_code_end.is_none() {
        log_error("kernel_verify", "Cannot determine kernel code size");
        return result;
    }

    let kernel_code_end = kernel_code_end.unwrap();
    let sig_offset = kernel_code_end;
    let sig_end = sig_offset + SIGNATURE_SIZE;

    if sig_end > kernel_data.len() {
        log_error("kernel_verify", "Signature offset out of bounds");
        return result;
    }

    let kernel_code = &kernel_data[..kernel_code_end];
    let signature = &kernel_data[sig_offset..sig_end];

    result.kernel_code_size = kernel_code.len();
    result.signature_present = true;

    print_kernel_size(st, kernel_code.len());
    mini_delay();

    compute_and_display_hash(kernel_code, &mut result, st);
    verify_and_display_signature(kernel_code, signature, &mut result, st);

    if result.signature_valid {
        print_verification_success(st);
    } else {
        print_verification_failure(st);
    }

    result
}

fn determine_kernel_boundary(kernel_data: &[u8]) -> Option<usize> {
    /* primary: compute from ELF header */
    if let Some(elf_size) = compute_elf_size(kernel_data) {
        log_debug("kernel_verify", "ELF size computed from header");
        return Some(elf_size);
    }

    /* fallback: search for ZK block */
    if let Some(zk_offset) = find_zk_block_offset(kernel_data) {
        log_debug("kernel_verify", "ZK block detected, computing kernel end");
        return Some(zk_offset - SIGNATURE_SIZE);
    }

    /* last resort: assume signature at end */
    if kernel_data.len() > SIGNATURE_SIZE {
        log_debug("kernel_verify", "Using fallback: total - signature");
        return Some(kernel_data.len() - SIGNATURE_SIZE);
    }

    None
}
