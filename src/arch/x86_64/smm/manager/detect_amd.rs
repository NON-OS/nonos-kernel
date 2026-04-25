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

use alloc::vec::Vec;

use super::state::SmmManager;
use crate::arch::x86_64::smm::constants::{amd_msr, LEGACY_SMRAM_BASE};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::read_msr;
use crate::arch::x86_64::smm::types::{SmmRegion, SmmRegionType};

impl SmmManager {
    pub(super) fn detect_amd_regions(&self, regions: &mut Vec<SmmRegion>) -> Result<(), SmmError> {
        let smm_base = unsafe { read_msr(amd_msr::SMM_BASE) };
        let smm_addr = unsafe { read_msr(amd_msr::SMM_ADDR) };
        let smm_mask = unsafe { read_msr(amd_msr::SMM_MASK) };

        let smm_enabled = (smm_mask & 1) != 0;
        let smm_locked = (smm_mask & amd_msr::LOCK_BIT) != 0;

        crate::log::info!("AMD SMM: enabled={}, locked={}", smm_enabled, smm_locked);

        if smm_enabled && smm_base > 0 {
            regions.push(SmmRegion {
                base: LEGACY_SMRAM_BASE,
                size: 0x10000,
                region_type: SmmRegionType::Aseg,
                protected: smm_locked,
                open: !smm_locked,
            });

            if smm_addr > 0 {
                let size = self.calculate_amd_smm_size(smm_mask);
                regions.push(SmmRegion {
                    base: smm_addr,
                    size,
                    region_type: SmmRegionType::Tseg,
                    protected: smm_locked,
                    open: !smm_locked,
                });
            }
        }
        Ok(())
    }

    fn calculate_amd_smm_size(&self, mask: u64) -> u64 {
        let addr_mask = mask & 0xFFFF_F000;
        if addr_mask == 0 {
            0x100000
        } else {
            (!addr_mask + 1) & 0xFFFF_FFFF
        }
    }
}
