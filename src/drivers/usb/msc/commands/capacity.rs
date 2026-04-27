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

use super::super::capacity::StorageCapacity;
use super::super::constants::*;
use super::super::scsi::send_scsi_command;
use super::super::state::MscDeviceState;

pub fn read_capacity_10(state: &MscDeviceState) -> Result<StorageCapacity, &'static str> {
    let cmd = [SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut data = [0u8; 8];
    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Read capacity (10) failed");
    }
    let last_lba = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64;
    let block_size = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let total_blocks = last_lba + 1;
    let total_bytes = total_blocks * block_size as u64;
    Ok(StorageCapacity { total_blocks, block_size, total_bytes })
}

pub fn read_capacity_16(state: &MscDeviceState) -> Result<StorageCapacity, &'static str> {
    let cmd = [SCSI_READ_CAPACITY_16, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0];
    let mut data = [0u8; 32];
    let csw = send_scsi_command(state, &cmd, Some(&mut data), None)?;
    if !csw.passed() {
        return Err("Read capacity (16) failed");
    }
    let last_lba = u64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let block_size = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let total_blocks = last_lba + 1;
    let total_bytes = total_blocks * block_size as u64;
    Ok(StorageCapacity { total_blocks, block_size, total_bytes })
}

pub fn get_capacity(state: &MscDeviceState) -> Result<StorageCapacity, &'static str> {
    match read_capacity_10(state) {
        Ok(cap) => {
            if cap.total_blocks >= 0xFFFFFFFF {
                read_capacity_16(state)
            } else {
                Ok(cap)
            }
        }
        Err(_) => read_capacity_16(state),
    }
}
