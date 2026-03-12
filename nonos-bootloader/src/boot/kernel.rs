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

use alloc::vec::Vec;
use uefi::prelude::*;

use crate::display::{
    draw_boot_progress, log_error as panel_error, log_hash, log_hex, log_size,
    show_error_screen, update_stage, StageStatus, STAGE_KERNEL_LOAD,
};
use crate::loader::load_kernel_binary;
use crate::log::logger::{log_error, log_info};

use super::uefi::TOTAL_BOOT_STAGES;
use super::util::fatal_reset;

pub fn run_kernel_load(
    system_table: &mut SystemTable<Boot>,
    gop_available: bool,
) -> Vec<u8> {
    update_stage(STAGE_KERNEL_LOAD, StageStatus::Running);
    draw_boot_progress(4, TOTAL_BOOT_STAGES);

    match load_kernel_binary(system_table) {
        Ok(data) => {
            log_info("loader", "kernel binary loaded");
            update_stage(STAGE_KERNEL_LOAD, StageStatus::Success);
            draw_boot_progress(5, TOTAL_BOOT_STAGES);

            if gop_available {
                log_size(b"kernel.bin ", data.len());
                log_hex(b"kernel base ", data.as_ptr() as u64);
                log_hex(
                    b"kernel end  ",
                    (data.as_ptr() as u64) + (data.len() as u64),
                );
                if data.len() >= 8 {
                    let mut magic = [0u8; 8];
                    magic.copy_from_slice(&data[..8]);
                    log_hash(b"ELF header  ", &magic);
                }
            }
            data
        }
        Err(_) => {
            log_error("loader", "kernel load failed");
            update_stage(STAGE_KERNEL_LOAD, StageStatus::Failed);
            if gop_available {
                panel_error(b"FATAL: kernel.bin not found");
                show_error_screen(b"Kernel not found at \\EFI\\nonos\\kernel.bin");
            }
            fatal_reset(system_table, "kernel not found");
        }
    }
}
