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
    animate_hash_reveal, draw_boot_progress, log_hash, log_ok,
    show_crypto_verification, show_error_screen, update_stage,
    BootCryptoState, StageStatus, STAGE_BLAKE3_HASH, STAGE_ED25519_VERIFY,
};
use crate::kernel_verify::{verify_kernel_crypto, CryptoVerifyResult};
use crate::log::logger::log_error;

use super::uefi::TOTAL_BOOT_STAGES;
use super::util::{fatal_reset, find_signature_end, micro_delay};

pub fn run_crypto_verification(
    system_table: &mut SystemTable<Boot>,
    kernel_data: &[u8],
    gop_available: bool,
) -> (CryptoVerifyResult, BootCryptoState) {
    let mut crypto_state = BootCryptoState::new();

    update_stage(STAGE_BLAKE3_HASH, StageStatus::Running);
    draw_boot_progress(5, TOTAL_BOOT_STAGES);

    let crypto_result = verify_kernel_crypto(kernel_data, system_table);

    crypto_state
        .kernel_hash
        .copy_from_slice(&crypto_result.kernel_hash_full);

    if gop_available {
        for _ in 0..32 {
            animate_hash_reveal();
            show_crypto_verification(&crypto_state);
            micro_delay();
        }
    }

    update_stage(STAGE_BLAKE3_HASH, StageStatus::Success);
    draw_boot_progress(6, TOTAL_BOOT_STAGES);

    if gop_available {
        log_ok(b"BLAKE3-256 hash computed");
        log_hash(b"BLAKE3 ", &crypto_result.kernel_hash_full);
    }

    update_stage(STAGE_ED25519_VERIFY, StageStatus::Running);
    draw_boot_progress(6, TOTAL_BOOT_STAGES);

    if kernel_data.len() >= 64 {
        let sig_end = find_signature_end(kernel_data);
        let sig_offset = sig_end - 64;
        crypto_state
            .signature_r
            .copy_from_slice(&kernel_data[sig_offset..sig_offset + 32]);
        crypto_state
            .signature_s
            .copy_from_slice(&kernel_data[sig_offset + 32..sig_offset + 64]);

        if gop_available {
            log_ok(b"Ed25519 signature extracted");
            log_hash(b"sig.R  ", &crypto_state.signature_r);
            log_hash(b"sig.S  ", &crypto_state.signature_s);
        }
    }

    crypto_state.signature_valid = Some(crypto_result.signature_valid);

    if gop_available {
        show_crypto_verification(&crypto_state);
    }

    if !crypto_result.signature_valid {
        log_error("crypto", "kernel signature verification FAILED");
        update_stage(STAGE_ED25519_VERIFY, StageStatus::Failed);
        if gop_available {
            crate::display::log_error(b"Ed25519 signature INVALID");
            show_error_screen(b"Kernel signature invalid - refusing to boot");
        }
        fatal_reset(system_table, "kernel signature invalid");
    }

    update_stage(STAGE_ED25519_VERIFY, StageStatus::Success);
    draw_boot_progress(7, TOTAL_BOOT_STAGES);

    if gop_available {
        log_ok(b"Ed25519 signature VALID");
    }

    (crypto_result, crypto_state)
}
