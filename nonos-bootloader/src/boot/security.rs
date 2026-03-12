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
    draw_boot_progress, log_info as panel_info, log_ok, show_error_screen,
    update_stage, StageStatus, STAGE_SECURITY,
};
use crate::log::logger::{log_error, log_warn};
use crate::security::{
    enforce_security_policy, initialize_security_subsystem,
    verify_secure_boot_chain, SecurityContext,
};

use super::uefi::TOTAL_BOOT_STAGES;
use super::util::fatal_reset;

pub fn run_security_checks(
    system_table: &mut SystemTable<Boot>,
    gop_available: bool,
) -> SecurityContext {
    update_stage(STAGE_SECURITY, StageStatus::Running);
    draw_boot_progress(2, TOTAL_BOOT_STAGES);

    let security = initialize_security_subsystem(system_table);

    if gop_available {
        if security.secure_boot_enabled {
            log_ok(b"SecureBoot ENABLED");
        } else {
            panel_info(b"SecureBoot disabled");
        }
        if security.measured_boot_active {
            log_ok(b"TPM2 MeasuredBoot active");
        } else {
            panel_info(b"TPM2 not available");
        }
    }

    let enforcement = enforce_security_policy(&security, system_table);
    if !enforcement.allow_boot {
        log_error("security", enforcement.reason);
        update_stage(STAGE_SECURITY, StageStatus::Failed);
        if gop_available {
            show_error_screen(b"Security policy enforcement failed");
        }
        fatal_reset(system_table, enforcement.reason);
    }

    if gop_available {
        log_ok(b"Security policy: ALLOW_BOOT");
    }

    if security.secure_boot_enabled && !verify_secure_boot_chain(&security, system_table) {
        log_warn("security", "Secure Boot chain verification warning");
    }

    update_stage(STAGE_SECURITY, StageStatus::Success);
    draw_boot_progress(3, TOTAL_BOOT_STAGES);

    security
}
