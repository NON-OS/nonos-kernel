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

use super::state::SmmManager;
use crate::arch::x86_64::smm::constants::{smramc_bits, SMRAMC_REGISTER};
use crate::arch::x86_64::smm::error::SmmError;
use crate::arch::x86_64::smm::hw::{read_pci_byte, write_pci_byte};

impl SmmManager {
    pub(super) fn enable_intel_protection(&self) -> Result<(), SmmError> {
        let mut smramc_val = read_pci_byte(0, 0, 0, SMRAMC_REGISTER);

        if (smramc_val & smramc_bits::D_LCK) == 0 {
            smramc_val |= smramc_bits::D_LCK;
            write_pci_byte(0, 0, 0, SMRAMC_REGISTER, smramc_val);
            crate::log::info!("Intel SMRAM: D_LCK set");
        }

        if (smramc_val & smramc_bits::D_OPEN) != 0 {
            smramc_val &= !smramc_bits::D_OPEN;
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
}
