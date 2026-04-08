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

use crate::arch::x86_64::smm::constants::{smramc, LEGACY_SMRAM_BASE, LEGACY_SMRAM_SIZE, SMRAMC_REGISTER};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{read_pci_byte, read_pci_dword};
use crate::arch::x86_64::smm::types::{SmmRegion, SmmRegionType};
use super::state::SmmManager;

impl SmmManager {
    pub(super) fn detect_intel_regions(&self, regions: &mut Vec<SmmRegion>) -> Result<(), SmmError> {
        let smramc = read_pci_byte(0, 0, 0, SMRAMC_REGISTER);
        let smram_enabled = (smramc & smramc::G_SMRAME) != 0;
        let d_open = (smramc & smramc::D_OPEN) != 0;
        let d_locked = (smramc & smramc::D_LCK) != 0;

        crate::log::info!("Intel SMRAMC: enabled={}, open={}, locked={}", smram_enabled, d_open, d_locked);

        if smram_enabled {
            regions.push(SmmRegion {
                base: LEGACY_SMRAM_BASE,
                size: LEGACY_SMRAM_SIZE,
                region_type: SmmRegionType::Aseg,
                protected: d_locked && !d_open,
                open: d_open,
            });
        }

        if let Some(tseg) = self.detect_intel_tseg() {
            regions.push(tseg);
        }
        Ok(())
    }

    fn detect_intel_tseg(&self) -> Option<SmmRegion> {
        let tseg_base = read_pci_dword(0, 0, 0, 0xB8) as u64;
        if tseg_base > 0 && tseg_base < 0xFFFF_FFFF {
            let tseg_size = 0x800000u64;
            Some(SmmRegion {
                base: tseg_base & 0xFFF0_0000,
                size: tseg_size,
                region_type: SmmRegionType::Tseg,
                protected: true,
                open: false,
            })
        } else {
            None
        }
    }
}
