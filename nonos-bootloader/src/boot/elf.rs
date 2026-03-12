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

extern crate alloc;

use alloc::format;
use uefi::prelude::*;

use crate::display::{
    draw_boot_progress, log_error as panel_error, log_hash, log_hex,
    log_ok, log_size, log_u32, show_error_screen, update_stage,
    StageStatus, STAGE_ELF_PARSE,
};
use crate::kernel_verify::CryptoVerifyResult;
use crate::loader::{load_kernel, KernelImage};
use crate::log::logger::{log_error, log_info};

use super::uefi::TOTAL_BOOT_STAGES;
use super::util::fatal_reset;

pub fn run_elf_parse(
    system_table: &mut SystemTable<Boot>,
    kernel_data: &[u8],
    crypto_result: &CryptoVerifyResult,
    gop_available: bool,
) -> KernelImage {
    update_stage(STAGE_ELF_PARSE, StageStatus::Running);
    draw_boot_progress(8, TOTAL_BOOT_STAGES);

    /*
     * Kernel layout: [elf_code][64-byte Ed25519 sig][optional ZK block]
     * Use kernel_code_size from crypto verification which accounts for this
     */
    let kernel_elf = if crypto_result.kernel_code_size > 0
        && crypto_result.kernel_code_size <= kernel_data.len()
    {
        &kernel_data[..crypto_result.kernel_code_size]
    } else if kernel_data.len() > 64 {
        &kernel_data[..kernel_data.len() - 64]
    } else {
        &kernel_data[..]
    };

    if gop_available {
        log_size(b"ELF len   ", kernel_elf.len());
        log_size(b"code_size ", crypto_result.kernel_code_size);
        if kernel_elf.len() >= 8 {
            let mut hdr = [0u8; 8];
            hdr.copy_from_slice(&kernel_elf[..8]);
            log_hash(b"ELF hdr   ", &hdr);
        }
    }

    match load_kernel(system_table, kernel_elf) {
        Ok(image) => {
            log_info("loader", "kernel loaded and verified");
            update_stage(STAGE_ELF_PARSE, StageStatus::Success);
            draw_boot_progress(9, TOTAL_BOOT_STAGES);

            if gop_available {
                log_ok(b"ELF64 parsed successfully");
                log_hex(b"entry   ", image.entry_point as u64);
                log_hex(b"base    ", image.address as u64);
                log_size(b"size    ", image.size);
                log_u32(b"segments ", image.alloc_count as u32);
            }
            image
        }
        Err(e) => {
            log_error("loader", &format!("ELF parsing failed: {}", e));
            update_stage(STAGE_ELF_PARSE, StageStatus::Failed);

            if gop_available {
                log_size(b"FAIL len  ", kernel_elf.len());
                log_size(b"FAIL code ", crypto_result.kernel_code_size);
                log_size(b"FAIL full ", kernel_data.len());
                let err_str = format!("{}", e);
                panel_error(err_str.as_bytes());
                panel_error(b"ELF parse failed");
                show_error_screen(b"Kernel ELF parsing failed");
            }
            fatal_reset(system_table, "kernel ELF parsing failed");
        }
    }
}
