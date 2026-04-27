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

pub fn write_blocks(
    state: &MscDeviceState,
    lba: u64,
    block_count: u16,
    data: &[u8],
) -> Result<usize, &'static str> {
    if lba > 0xFFFFFFFF {
        return Err("LBA too large for WRITE(10)");
    }
    let lba_bytes = (lba as u32).to_be_bytes();
    let count_bytes = block_count.to_be_bytes();
    let cmd = [
        SCSI_WRITE_10,
        0,
        lba_bytes[0],
        lba_bytes[1],
        lba_bytes[2],
        lba_bytes[3],
        0,
        count_bytes[0],
        count_bytes[1],
        0,
    ];
    let csw = send_scsi_command(state, &cmd, None, Some(data))?;
    if !csw.passed() {
        return Err("Write failed");
    }
    Ok(data.len() - csw.d_csw_data_residue as usize)
}

pub fn write_blocks_16(
    state: &MscDeviceState,
    lba: u64,
    block_count: u32,
    data: &[u8],
) -> Result<usize, &'static str> {
    let lba_bytes = lba.to_be_bytes();
    let count_bytes = block_count.to_be_bytes();
    let cmd = [
        SCSI_WRITE_16,
        0,
        lba_bytes[0],
        lba_bytes[1],
        lba_bytes[2],
        lba_bytes[3],
        lba_bytes[4],
        lba_bytes[5],
        lba_bytes[6],
        lba_bytes[7],
        count_bytes[0],
        count_bytes[1],
        count_bytes[2],
        count_bytes[3],
        0,
        0,
    ];
    let csw = send_scsi_command(state, &cmd, None, Some(data))?;
    if !csw.passed() {
        return Err("Write(16) failed");
    }
    Ok(data.len() - csw.d_csw_data_residue as usize)
}

pub fn write_blocks_auto(
    state: &MscDeviceState,
    lba: u64,
    block_count: u32,
    data: &[u8],
) -> Result<usize, &'static str> {
    if lba > 0xFFFFFFFF || block_count > 0xFFFF {
        write_blocks_16(state, lba, block_count, data)
    } else {
        write_blocks(state, lba, block_count as u16, data)
    }
}
