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

use uefi::cstr16;
use uefi::prelude::*;

use crate::log::logger::log_warn;
use crate::security::EnforcementResult;

pub fn display_enforcement_result(result: &EnforcementResult, st: &mut SystemTable<Boot>) {
    if result.allow_boot {
        let _ = st.stdout().output_string(cstr16!("[SECURITY] PASSED\r\n"));
    } else {
        let _ = st.stdout().output_string(cstr16!("[SECURITY] BLOCKED\r\n"));
    }

    for i in 0..result.warning_count {
        if let Some(warning) = result.warnings[i] {
            log_warn("enforce", warning);
        }
    }
}
