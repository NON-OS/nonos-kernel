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

use core::sync::atomic::Ordering;

use super::state::SmmManager;
use crate::arch::x86_64::smm::constants::{LEGACY_SMRAM_BASE, LEGACY_SMRAM_SIZE};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::types::{CpuVendor, SmmRegion, SmmRegionType};

impl SmmManager {
    pub(crate) fn detect_regions(&self, vendor: CpuVendor) -> Result<(), SmmError> {
        let mut regions = self.regions.write();

        match vendor {
            CpuVendor::Intel => self.detect_intel_regions(&mut regions)?,
            CpuVendor::Amd => self.detect_amd_regions(&mut regions)?,
            CpuVendor::Unknown => {
                regions.push(SmmRegion {
                    base: LEGACY_SMRAM_BASE,
                    size: LEGACY_SMRAM_SIZE,
                    region_type: SmmRegionType::Aseg,
                    protected: false,
                    open: true,
                });
            }
        }

        self.stats
            .regions_protected
            .store(regions.iter().filter(|r| r.protected).count() as u64, Ordering::SeqCst);
        Ok(())
    }
}
