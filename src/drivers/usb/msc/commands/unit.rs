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

use super::super::constants::*;
use super::super::scsi::send_scsi_command;
use super::super::sense::SenseData;
use super::super::state::MscDeviceState;

pub fn test_unit_ready(state: &MscDeviceState) -> Result<bool, &'static str> {
    let cmd = [SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0];
    let csw = send_scsi_command(state, &cmd, None, None)?;
    Ok(csw.passed())
}

pub fn request_sense(state: &MscDeviceState) -> Result<SenseData, &'static str> {
    let cmd = [SCSI_REQUEST_SENSE, 0, 0, 0, 18, 0];
    let mut data = [0u8; 18];
    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Request sense failed");
    }
    SenseData::parse(&data).ok_or("Invalid sense data")
}
