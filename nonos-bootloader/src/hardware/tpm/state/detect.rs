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
use crate::hardware::tpm::constants::{TPM_DID_VID, TPM_INTERFACE_ID};
use crate::hardware::tpm::types::TpmError;

impl TpmState {
    pub fn detect(&mut self) -> Result<bool, TpmError> {
        let did_vid = self.read_reg32(TPM_DID_VID);
        if did_vid == 0 || did_vid == 0xFFFF_FFFF {
            return Ok(false);
        }

        let interface_id = self.read_reg32(TPM_INTERFACE_ID);
        self.version = if (interface_id & 0x0F) == 0x00 { 12 } else { 20 };

        self.initialized = true;
        Ok(true)
    }
}
