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

use crate::display::{
    draw_boot_progress, log_error as panel_error, log_hash,
    log_info as panel_info, log_ok, show_crypto_verification,
    show_error_screen, update_stage, BootCryptoState, StageStatus,
    STAGE_ZK_VERIFY,
};
use crate::log::logger::{log_error, log_info};
use crate::security::extend_boot_measurements;
use crate::zk::{has_zk_proof, verify_boot_attestation, BootAttestationResult};

use super::uefi::TOTAL_BOOT_STAGES;
use super::util::fatal_reset;

pub fn run_zk_attestation(
    system_table: &mut SystemTable<Boot>,
    kernel_data: &[u8],
    kernel_hash: &[u8; 32],
    crypto_state: &mut BootCryptoState,
    gop_available: bool,
    tpm_measured: bool,
) -> BootAttestationResult {
    update_stage(STAGE_ZK_VERIFY, StageStatus::Running);
    draw_boot_progress(7, TOTAL_BOOT_STAGES);

    let has_proof = has_zk_proof(kernel_data);
    let zk_result = verify_boot_attestation(kernel_data);

    if gop_available {
        if has_proof {
            log_ok(b"ZK proof block found");
        } else {
            panel_info(b"ZK proof not present");
        }
    }

    crypto_state.zk_present = has_proof;
    crypto_state
        .zk_program_hash
        .copy_from_slice(&zk_result.program_hash);
    crypto_state.zk_verified = Some(zk_result.zk_verified);

    if gop_available {
        show_crypto_verification(crypto_state);
    }

    if !has_proof {
        log_error("zk", "ZK attestation REQUIRED - no proof found in kernel");
        update_stage(STAGE_ZK_VERIFY, StageStatus::Failed);
        if gop_available {
            panel_error(b"ZK proof MISSING");
            show_error_screen(b"ZK attestation required - use embed-zk-proof tool");
        }
        fatal_reset(system_table, "ZK proof missing - attestation required");
    }

    if !zk_result.zk_verified {
        log_error("zk", "ZK attestation verification FAILED");
        log_error("zk", zk_result.status_message);
        update_stage(STAGE_ZK_VERIFY, StageStatus::Failed);
        if gop_available {
            panel_error(b"ZK attestation FAILED");
            show_error_screen(b"ZK attestation invalid - Groth16 verification failed");
        }
        fatal_reset(system_table, zk_result.status_message);
    }

    log_info("zk", "ZK attestation VERIFIED (Groth16/BLS12-381)");
    update_stage(STAGE_ZK_VERIFY, StageStatus::Success);
    draw_boot_progress(8, TOTAL_BOOT_STAGES);

    if gop_available {
        log_ok(b"Groth16/BLS12-381 VERIFIED");
        log_hash(b"ZK prog ", &zk_result.program_hash);
        log_hash(b"capsule ", &zk_result.capsule_commitment);
    }

    if tpm_measured {
        let mut sig_bytes = [0u8; 64];
        if kernel_data.len() >= 64 {
            sig_bytes.copy_from_slice(&kernel_data[kernel_data.len() - 64..]);
        }
        extend_boot_measurements(
            system_table,
            kernel_hash,
            &sig_bytes,
            &zk_result.program_hash,
        );
        log_info("tpm", "boot measurements extended to TPM");
    }

    zk_result
}
