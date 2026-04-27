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
use super::super::state::MscDeviceState;

pub fn sync_cache(state: &MscDeviceState) -> Result<(), &'static str> {
    let cmd = [SCSI_SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let csw = send_scsi_command(state, &cmd, None, None)?;
    if !csw.passed() {
        return Err("Sync cache failed");
    }
    Ok(())
}

pub fn is_write_protected(state: &MscDeviceState) -> Result<bool, &'static str> {
    let cmd = [SCSI_MODE_SENSE_6, 0, 0x3F, 0, 192, 0];
    let mut data = [0u8; 192];
    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Ok(false);
    }
    let device_specific = data[2];
    Ok((device_specific & 0x80) != 0)
}

pub fn eject_media(state: &MscDeviceState, eject: bool) -> Result<(), &'static str> {
    let cmd = [SCSI_START_STOP_UNIT, 0, 0, 0, if eject { 0x02 } else { 0x03 }, 0];
    let csw = send_scsi_command(state, &cmd, None, None)?;
    if !csw.passed() {
        return Err("Start/stop unit failed");
    }
    Ok(())
}

pub fn lock_media(state: &MscDeviceState, lock: bool) -> Result<(), &'static str> {
    let cmd = [SCSI_PREVENT_ALLOW_MEDIUM_REMOVAL, 0, 0, 0, if lock { 0x01 } else { 0x00 }, 0];
    let csw = send_scsi_command(state, &cmd, None, None)?;
    if !csw.passed() {
        return Err("Prevent/allow medium removal failed");
    }
    Ok(())
}
