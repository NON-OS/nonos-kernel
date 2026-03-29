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

use super::core::TpmState;
use crate::hardware::tpm::constants::{TPM_ACCESS, TPM_ACCESS_ACTIVE, TPM_ACCESS_REQUEST, TPM_STS};
use crate::hardware::tpm::types::TpmError;

impl TpmState {
    pub fn request_locality(&self) -> Result<(), TpmError> {
        if !self.initialized {
            return Err(TpmError::NotPresent);
        }

        self.write_reg8(TPM_ACCESS, TPM_ACCESS_REQUEST);

        for _ in 0..1000 {
            let access = self.read_reg8(TPM_ACCESS);
            if (access & TPM_ACCESS_ACTIVE) != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(TpmError::Timeout)
    }

    pub fn release_locality(&self) {
        if self.initialized {
            self.write_reg8(TPM_ACCESS, TPM_ACCESS_ACTIVE);
        }
    }

    pub(crate) fn wait_for_status(&self, mask: u8, expected: u8) -> Result<(), TpmError> {
        for _ in 0..10000 {
            let sts = self.read_reg8(TPM_STS);
            if (sts & mask) == expected {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(TpmError::Timeout)
    }
}
