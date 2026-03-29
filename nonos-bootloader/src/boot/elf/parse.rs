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

use super::display::{display_elf_info, display_load_failure, display_loaded_image};
use super::extract::extract_kernel_payload;
use crate::boot::uefi::TOTAL_BOOT_STAGES;
use crate::boot::util::fatal_reset;
use crate::display::{draw_boot_progress, update_stage, StageStatus, STAGE_ELF_PARSE};
use crate::kernel_verify::CryptoVerifyResult;
use crate::loader::{load_kernel, KernelImage};
use crate::log::logger::{log_error, log_info};

pub fn run_elf_parse(
    system_table: &mut SystemTable<Boot>,
    kernel_data: &[u8],
    crypto_result: &CryptoVerifyResult,
    gop_available: bool,
) -> KernelImage {
    update_stage(STAGE_ELF_PARSE, StageStatus::Running);
    draw_boot_progress(8, TOTAL_BOOT_STAGES);

    let kernel_elf = extract_kernel_payload(kernel_data, system_table);

    display_elf_info(kernel_elf, crypto_result, gop_available);

    match load_kernel(system_table, kernel_elf) {
        Ok(image) => {
            log_info("loader", "kernel loaded and verified");
            update_stage(STAGE_ELF_PARSE, StageStatus::Success);
            draw_boot_progress(9, TOTAL_BOOT_STAGES);
            display_loaded_image(&image, gop_available);
            image
        }
        Err(e) => {
            log_error("loader", &format!("ELF parsing failed: {}", e));
            update_stage(STAGE_ELF_PARSE, StageStatus::Failed);
            display_load_failure(kernel_elf, crypto_result, kernel_data, gop_available, &e);
            fatal_reset(system_table, "kernel ELF parsing failed");
        }
    }
}
