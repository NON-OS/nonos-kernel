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

use crate::arch::x86_64::smm::constants::amd_msr;
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{read_msr, write_msr};
use super::state::SmmManager;

impl SmmManager {
    pub(super) fn enable_amd_protection(&self) -> Result<(), SmmError> {
        let mut smm_mask = unsafe { read_msr(amd_msr::SMM_MASK) };

        if (smm_mask & amd_msr::LOCK_BIT) == 0 {
            smm_mask |= amd_msr::LOCK_BIT;
            unsafe { write_msr(amd_msr::SMM_MASK, smm_mask) };
            crate::log::info!("AMD SMM: lock bit set");
        }

        let mut regions = self.regions.write();
        for region in regions.iter_mut() {
            region.protected = true;
            region.open = false;
        }
        Ok(())
    }
}
