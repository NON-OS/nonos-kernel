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

use crate::config::load_bootloader_config;
use crate::display::{
    draw_boot_progress, init_boot_screen, init_gop, init_main_screen, log_hex, log_ok, log_u32,
    update_stage, StageStatus, STAGE_UEFI,
};
use crate::firmware::detect_firmware_quirks;
use crate::log::logger::{init_logger, log_info};

pub const TOTAL_BOOT_STAGES: u32 = 10;

pub struct UefiInitResult {
    pub gop_available: bool,
}

pub fn run_uefi_init(system_table: &mut SystemTable<Boot>) -> UefiInitResult {
    let gop_available = init_gop(system_table);
    init_logger(system_table);
    log_info("boot", "UEFI services initialized");
    let _config = load_bootloader_config(system_table);
    let _quirks = detect_firmware_quirks(system_table);
    log_info("firmware", "detected firmware quirks");

    if gop_available {
        init_main_screen();
    }

    UefiInitResult { gop_available }
}

pub fn run_boot_screen_init(system_table: &mut SystemTable<Boot>, gop_available: bool) {
    if !gop_available {
        return;
    }
    init_boot_screen();
    draw_boot_progress(1, TOTAL_BOOT_STAGES);
    log_ok(b"GOP framebuffer initialized");
    update_stage(STAGE_UEFI, StageStatus::Success);
    log_hex(b"SystemTable     ", system_table as *const _ as u64);
    log_hex(b"BootServices    ", system_table.boot_services() as *const _ as u64);
    log_hex(b"RuntimeServices ", system_table.runtime_services() as *const _ as u64);
    log_hex(b"ConfigTable     ", system_table.config_table().as_ptr() as u64);
    log_u32(b"ConfigTableCount ", system_table.config_table().len() as u32);
    log_ok(b"boot.toml loaded");
}
