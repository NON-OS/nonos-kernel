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

use uefi::prelude::*;

use super::enforce::enforce_zk_binding;
use crate::display::{
    draw_boot_progress, log_error as panel_error, log_hash, log_ok, show_error_screen,
    update_stage, BootCryptoState, StageStatus, STAGE_ZK_VERIFY,
};
use crate::log::logger::{log_error, log_info};
use crate::security::extend_boot_measurements;
use crate::zk::{has_zk_proof, verify_boot_attestation, BootAttestationResult};

use super::super::uefi::TOTAL_BOOT_STAGES;
use super::super::util::fatal_reset;

pub fn run_zk_attestation(
    st: &mut SystemTable<Boot>,
    kernel_data: &[u8],
    kernel_hash: &[u8; 32],
    crypto_state: &mut BootCryptoState,
    gop_available: bool,
    tpm_measured: bool,
) -> BootAttestationResult {
    update_stage(STAGE_ZK_VERIFY, StageStatus::Running);
    draw_boot_progress(7, TOTAL_BOOT_STAGES);

    enforce_proof_presence(st, kernel_data, gop_available);

    let zk_result = verify_boot_attestation(kernel_data);

    enforce_verification_success(st, &zk_result, gop_available);

    enforce_zk_binding(st, &zk_result, kernel_data, kernel_hash, gop_available);

    update_crypto_state(crypto_state, &zk_result);
    display_success(st, &zk_result, kernel_hash, gop_available, tpm_measured);

    log_info("zk", "ZK attestation VERIFIED with kernel binding");
    update_stage(STAGE_ZK_VERIFY, StageStatus::Success);
    draw_boot_progress(8, TOTAL_BOOT_STAGES);

    zk_result
}

fn enforce_proof_presence(st: &mut SystemTable<Boot>, data: &[u8], gop: bool) {
    if !has_zk_proof(data) {
        log_error("zk", "ZK attestation REQUIRED - no proof found");
        update_stage(STAGE_ZK_VERIFY, StageStatus::Failed);
        if gop {
            panel_error(b"ZK proof MISSING");
            show_error_screen(b"ZK attestation required");
        }
        fatal_reset(st, "ZK proof missing");
    }
}

fn enforce_verification_success(st: &mut SystemTable<Boot>, r: &BootAttestationResult, gop: bool) {
    if !r.zk_verified {
        log_error("zk", "ZK verification FAILED");
        log_error("zk", r.status_message);
        update_stage(STAGE_ZK_VERIFY, StageStatus::Failed);
        if gop {
            panel_error(b"ZK verification FAILED");
            show_error_screen(r.status_message.as_bytes());
        }
        fatal_reset(st, r.status_message);
    }
}

fn update_crypto_state(state: &mut BootCryptoState, result: &BootAttestationResult) {
    state.zk_present = true;
    state.zk_program_hash.copy_from_slice(&result.program_hash);
    state.zk_verified = Some(result.zk_verified);
}

fn display_success(
    st: &mut SystemTable<Boot>,
    r: &BootAttestationResult,
    kh: &[u8; 32],
    gop: bool,
    tpm: bool,
) {
    if gop {
        log_ok(b"Groth16/BLS12-381 VERIFIED");
        log_ok(b"Kernel binding VERIFIED");
        log_hash(b"ZK prog ", &r.program_hash);
        log_hash(b"capsule ", &r.capsule_commitment);
    }

    if tpm {
        let sig = [0u8; 64];
        extend_boot_measurements(st, kh, &sig, &r.program_hash);
        log_info("tpm", "measurements extended");
    }
}
