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
    draw_boot_progress, log_error as panel_error, log_hash, log_hex, log_ok,
    show_error_screen, show_handoff_message, update_stage, StageStatus,
    STAGE_COMPLETE, STAGE_HANDOFF,
};
use crate::entropy::collect_boot_entropy_64;
use crate::firmware::get_firmware_handoff;
use crate::handoff::{exit_and_jump, CryptoHandoff};
use crate::loader::KernelImage;
use crate::log::logger::{log_error, log_info};
use crate::zk::BootAttestationResult;

use super::uefi::TOTAL_BOOT_STAGES;
use super::util::{fatal_reset, mini_delay};

pub struct HandoffParams {
    pub signature_valid: bool,
    pub secure_boot: bool,
    pub kernel_hash: [u8; 32],
    pub zk_result: BootAttestationResult,
    pub tpm_measured: bool,
}

pub fn run_handoff_prepare(
    system_table: SystemTable<Boot>,
    kernel_image: &KernelImage,
    params: HandoffParams,
    gop_available: bool,
) -> ! {
    let mut st = system_table;

    log_info("handoff", "starting handoff preparation");
    update_stage(STAGE_HANDOFF, StageStatus::Running);
    draw_boot_progress(10, TOTAL_BOOT_STAGES);
    log_info("handoff", "collecting entropy");

    let crypto_handoff = CryptoHandoff {
        signature_valid: params.signature_valid,
        secure_boot: params.secure_boot,
        kernel_hash: params.kernel_hash,
        zk_attested: params.zk_result.zk_verified,
        zk_program_hash: params.zk_result.program_hash,
        zk_capsule_commitment: params.zk_result.capsule_commitment,
    };

    let entropy = match collect_boot_entropy_64(&st) {
        Ok(e) => e,
        Err(msg) => {
            log_error("entropy", msg);
            if gop_available {
                panel_error(b"Entropy collection failed");
                show_error_screen(b"Insufficient entropy for secure boot");
            }
            fatal_reset(&mut st, "entropy collection failed");
        }
    };

    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&entropy[..32]);
    log_info("handoff", "entropy collected, preparing handoff");

    let firmware_handoff = get_firmware_handoff();
    log_info("firmware", "firmware handoff prepared");

    if gop_available {
        log_ok(b"Entropy collected");
        log_hash(b"RNGseed ", &rng_seed);
        log_ok(b"CryptoHandoff prepared");
        log_ok(b"FirmwareHandoff prepared");
    }

    update_stage(STAGE_HANDOFF, StageStatus::Success);
    update_stage(STAGE_COMPLETE, StageStatus::Success);
    draw_boot_progress(TOTAL_BOOT_STAGES, TOTAL_BOOT_STAGES);

    if gop_available {
        log_ok(b"All boot stages COMPLETE");
        log_hex(b"jumping ", kernel_image.entry_point as u64);
        show_handoff_message();
    }
    mini_delay();

    log_info("handoff", "transferring control to kernel");

    exit_and_jump(
        st,
        kernel_image,
        None,
        crypto_handoff,
        firmware_handoff,
        rng_seed,
        params.tmp_measured,
    );
}
