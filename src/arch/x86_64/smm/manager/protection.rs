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

use crate::arch::x86_64::smm::constants::{amd_msr, smramc, SMRAMC_REGISTER};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{read_msr, read_pci_byte, write_msr, write_pci_byte};
use crate::arch::x86_64::smm::types::CpuVendor;
use super::state::SmmManager;

impl SmmManager {
    pub(crate) fn enable_protection(&self, vendor: CpuVendor) -> Result<(), SmmError> {
        match vendor {
            CpuVendor::Intel => self.enable_intel_protection()?,
            CpuVendor::Amd => self.enable_amd_protection()?,
            CpuVendor::Unknown => {
                crate::log::info!("Unknown CPU, skipping SMM protection");
            }
        }

        self.protection_enabled.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn enable_intel_protection(&self) -> Result<(), SmmError> {
        let mut smramc_val = read_pci_byte(0, 0, 0, SMRAMC_REGISTER);

        if (smramc_val & smramc::D_LCK) == 0 {
            smramc_val |= smramc::D_LCK;
            write_pci_byte(0, 0, 0, SMRAMC_REGISTER, smramc_val);
            crate::log::info!("Intel SMRAM: D_LCK set");
        }

        if (smramc_val & smramc::D_OPEN) != 0 {
            smramc_val &= !smramc::D_OPEN;
            write_pci_byte(0, 0, 0, SMRAMC_REGISTER, smramc_val);
            crate::log::info!("Intel SMRAM: D_OPEN cleared");
        }

        let mut regions = self.regions.write();
        for region in regions.iter_mut() {
            region.protected = true;
            region.open = false;
        }

        Ok(())
    }

    fn enable_amd_protection(&self) -> Result<(), SmmError> {
        // SAFETY: Reading AMD SMM MSR during protection enable
        let mut smm_mask = unsafe { read_msr(amd_msr::SMM_MASK) };

        if (smm_mask & amd_msr::LOCK_BIT) == 0 {
            smm_mask |= amd_msr::LOCK_BIT;
            // SAFETY: Writing AMD SMM MSR to enable lock bit
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
