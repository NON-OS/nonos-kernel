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

use crate::log::logger::log_warn;
use crate::security::enforce::policy::EnforcementResult;
use crate::security::types::SecurityContext;

pub fn enforce_development(ctx: &SecurityContext, result: &mut EnforcementResult) {
    log_warn("enforce", "DEVELOPMENT MODE - security features non-mandatory");

    if !ctx.secure_boot_enabled {
        result.warn("SecureBoot disabled");
    }

    if !ctx.measured_boot_active {
        result.warn("TPM not available");
    }

    if !ctx.hardware_rng_available {
        result.warn("HW RNG not available");
    }

    if !ctx.platform_key_verified {
        result.warn("PlatformKey not verified");
    }
}
