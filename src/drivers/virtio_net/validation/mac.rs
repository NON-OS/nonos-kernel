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

use super::super::error::VirtioNetError;

pub fn validate_mac_address(mac: &[u8; 6]) -> Result<(), VirtioNetError> {
    if mac.iter().all(|&b| b == 0) { return Err(VirtioNetError::InvalidMacAddress); }
    if mac.iter().all(|&b| b == 0xFF) { return Err(VirtioNetError::InvalidMacAddress); }
    Ok(())
}

pub fn validate_source_mac(mac: &[u8; 6]) -> Result<(), VirtioNetError> {
    validate_mac_address(mac)?;
    if mac[0] & 0x01 != 0 { return Err(VirtioNetError::InvalidMacAddress); }
    Ok(())
}
