// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

use crate::arch::x86_64::smm::constants::intel_msr;
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{read_msr, write_msr};
use crate::arch::x86_64::smm::manager::SMM_MANAGER;
use crate::arch::x86_64::smm::types::CpuVendor;

pub fn enable_runtime_protection() -> Result<(), SmmError> {
    let vendor = SMM_MANAGER.cpu_vendor();
    if vendor != CpuVendor::Intel { return Ok(()); }

    unsafe {
        let mut smm_feature = read_msr(intel_msr::SMM_FEATURE_CONTROL);
        if (smm_feature & intel_msr::SMM_CODE_CHK_EN) == 0 {
            smm_feature |= intel_msr::SMM_CODE_CHK_EN;
            write_msr(intel_msr::SMM_FEATURE_CONTROL, smm_feature);
            crate::log::info!("Enabled SMM_Code_Chk_En");
        }
        if (smm_feature & intel_msr::SMM_BWP) == 0 {
            smm_feature |= intel_msr::SMM_BWP;
            write_msr(intel_msr::SMM_FEATURE_CONTROL, smm_feature);
            crate::log::info!("Enabled SMM_BWP");
        }
    }

    crate::log::info!("SMM runtime protection enabled");
    Ok(())
}
