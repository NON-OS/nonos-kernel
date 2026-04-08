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

use crate::arch::x86_64::smm::constants::cr4;
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{read_cr4, write_cr4};

pub fn enable_smm_sandboxing() -> Result<(), SmmError> {
    let result = core::arch::x86_64::__cpuid(7);
    let smep_supported = (result.ebx & (1 << 7)) != 0;
    let smap_supported = (result.ebx & (1 << 20)) != 0;

    unsafe {
        let mut cr4_val = read_cr4();
        if smep_supported && (cr4_val & cr4::SMEP) == 0 {
            cr4_val |= cr4::SMEP;
            crate::log::info!("Enabling SMEP for SMM sandboxing");
        }
        if smap_supported && (cr4_val & cr4::SMAP) == 0 {
            cr4_val |= cr4::SMAP;
            crate::log::info!("Enabling SMAP for SMM sandboxing");
        }
        write_cr4(cr4_val);
    }

    crate::log::info!("SMM sandboxing: SMEP={}, SMAP={}", smep_supported, smap_supported);
    Ok(())
}
