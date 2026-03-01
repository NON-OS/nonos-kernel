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

use super::constants::{CSW_SIGNATURE, CSW_STATUS_PASSED};

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct CommandStatusWrapper {
    pub d_csw_signature: u32,
    pub d_csw_tag: u32,
    pub d_csw_data_residue: u32,
    pub b_csw_status: u8,
}

impl CommandStatusWrapper {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 13 {
            return None;
        }

        let mut csw = Self::default();
        csw.d_csw_signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        csw.d_csw_tag = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        csw.d_csw_data_residue = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        csw.b_csw_status = data[12];

        if csw.d_csw_signature != CSW_SIGNATURE {
            return None;
        }

        Some(csw)
    }

    pub fn is_valid(&self) -> bool {
        self.d_csw_signature == CSW_SIGNATURE
    }

    pub fn passed(&self) -> bool {
        self.b_csw_status == CSW_STATUS_PASSED
    }
}
